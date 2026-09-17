//! HTTP CONNECT proxy support for outbound tunnel connections.
//!
//! EasyTier normally dials `tcp://`, `ws://` and `wss://` peers directly.
//! When a proxy is configured, the transport layer first connects to the
//! proxy server and then issues an HTTP `CONNECT` request so that the proxy
//! tunnels the connection to the target peer address. This allows nodes that
//! cannot reach a peer directly (e.g. behind a firewall that only allows
//! traffic through an HTTP proxy) to join the network.

use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, OnceLock},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

/// Upper bound for the proxy's HTTP response header block.
const MAX_PROXY_RESPONSE_HEADER_BYTES: usize = 64 * 1024;

/// How long a single HTTP CONNECT handshake may take.
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// A configured HTTP CONNECT proxy server.
#[derive(Debug, Clone)]
pub struct HttpProxyConfig {
    url: url::Url,
}

impl HttpProxyConfig {
    fn new(url: url::Url) -> anyhow::Result<Self> {
        if !matches!(url.scheme(), "http" | "https") {
            anyhow::bail!("unsupported http proxy scheme: {}", url.scheme());
        }
        if url.host_str().is_none_or(str::is_empty) {
            anyhow::bail!("http proxy url must contain a host: {url}");
        }
        if url.port().is_none() {
            anyhow::bail!("http proxy url must contain a port: {url}");
        }
        Ok(Self { url })
    }

    /// `host:port` of the proxy server (IPv6 addresses are bracketed).
    fn proxy_authority(&self) -> String {
        let host = self.url.host_str().unwrap_or_default();
        let port = self.url.port().unwrap();
        format_authority(host, port)
    }

    /// Resolves the proxy server to a concrete socket address.
    pub(crate) async fn proxy_socket_addr(&self) -> anyhow::Result<SocketAddr> {
        let host = self.url.host_str().unwrap_or_default();
        let port = self.url.port().unwrap();
        let mut addrs = tokio::net::lookup_host((host, port)).await.with_context(|| {
            format!("failed to resolve http proxy server {host}:{port}")
        })?;
        addrs
            .next()
            .ok_or_else(|| anyhow::anyhow!("http proxy server {host}:{port} has no address"))
    }

    /// Basic authentication credentials embedded in the proxy URL, if any.
    fn credentials(&self) -> Option<(String, String)> {
        let username = percent_decode(self.url.username());
        let password = percent_decode(self.url.password().unwrap_or_default());
        if username.is_empty() && password.is_empty() {
            None
        } else {
            Some((username, password))
        }
    }

    fn authorization_header(&self) -> Option<String> {
        let (username, password) = self.credentials()?;
        use base64::Engine as _;
        let token = base64::engine::general_purpose::STANDARD
            .encode(format!("{username}:{password}"));
        Some(format!("Basic {token}"))
    }
}

fn percent_decode(value: &str) -> String {
    percent_encoding::percent_decode_str(value)
        .decode_utf8_lossy()
        .into_owned()
}

fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        // IPv6 literal.
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Explicitly configured proxy. Once set it wins over environment variables.
static HTTP_PROXY: OnceLock<Option<Arc<HttpProxyConfig>>> = OnceLock::new();

/// Sets the HTTP proxy from a user-supplied URL (e.g. `--http-proxy`).
pub fn set_http_proxy(proxy_url: Option<&str>) -> anyhow::Result<()> {
    let config = match proxy_url {
        Some(url) => Some(Arc::new(HttpProxyConfig::new(url.parse().with_context(
            || format!("failed to parse http proxy url: {url}"),
        )?)?)),
        None => None,
    };
    let _ = HTTP_PROXY.set(config);
    Ok(())
}

/// Returns the active HTTP proxy configuration.
///
/// When no proxy was configured explicitly, common proxy environment
/// variables are consulted in order: `HTTPS_PROXY`, `http_proxy`,
/// `ALL_PROXY`, `all_proxy`.
pub fn http_proxy() -> Option<Arc<HttpProxyConfig>> {
    HTTP_PROXY
        .get_or_init(|| {
            for name in ["HTTPS_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
                if let Ok(value) = std::env::var(name) {
                    let value = value.trim();
                    if value.is_empty() {
                        continue;
                    }
                    match value.parse::<url::Url>() {
                        Ok(url) => match HttpProxyConfig::new(url) {
                            Ok(config) => return Some(Arc::new(config)),
                            Err(error) => {
                                tracing::warn!(
                                    %name,
                                    %error,
                                    "ignoring invalid http proxy from environment",
                                );
                            }
                        },
                        Err(error) => {
                            tracing::warn!(%name, %error, "ignoring invalid http proxy url");
                        }
                    }
                }
            }
            None
        })
        .clone()
}

/// Whether a connection to `target` should be routed through the proxy.
///
/// Loopback, link-local and unspecified addresses are always dialed
/// directly so that local listeners keep working without a proxy.
pub fn should_route_through_proxy(target: SocketAddr) -> bool {
    let ip = target.ip();
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback() || v4.is_unspecified() || v4.is_multicast() || v4.is_link_local()
                || is_private_if_required(v4))
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() || v6.is_unicast_link_local())
        }
    }
}

fn is_private_if_required(ip: std::net::Ipv4Addr) -> bool {
    // RFC 1918 / CGNAT ranges. These usually indicate an intra-site peer
    // that should not be sent through a proxy.
    matches!(
        (ip.octets()[0], ip.octets()[1]),
        (10, _) | (172, 16..=31) | (192, 168) | (100, 64..=127)
    )
}

/// Performs an HTTP CONNECT handshake over an already-connected stream.
///
/// On success the stream is a tunnel to `target` and can be used as if it
/// were a direct connection.
pub async fn http_connect(
    stream: &mut TcpStream,
    target: SocketAddr,
    proxy: &HttpProxyConfig,
) -> anyhow::Result<()> {
    let target_authority = target.to_string();
    let mut request = format!(
        "CONNECT {target_authority} HTTP/1.1\r\nHost: {target_authority}\r\nProxy-Connection: Keep-Alive\r\nUser-Agent: easytier\r\n"
    );
    if let Some(authorization) = proxy.authorization_header() {
        request.push_str(&format!("Proxy-Authorization: {authorization}\r\n"));
    }
    request.push_str("\r\n");

    tokio::time::timeout(HTTP_CONNECT_TIMEOUT, async {
        stream
            .write_all(request.as_bytes())
            .await
            .with_context(|| "failed to send http CONNECT request to proxy")?;
        stream
            .flush()
            .await
            .with_context(|| "failed to flush http CONNECT request to proxy")?;

        let mut response = Vec::with_capacity(512);
        let mut buffer = [0u8; 1024];
        loop {
            if response.len() > MAX_PROXY_RESPONSE_HEADER_BYTES {
                anyhow::bail!("http proxy response header is too large");
            }
            let read = stream
                .read(&mut buffer)
                .await
                .with_context(|| "failed to read http CONNECT response from proxy")?;
            if read == 0 {
                anyhow::bail!("http proxy closed the connection during CONNECT handshake");
            }
            response.extend_from_slice(&buffer[..read]);
            if response.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }

        let response = String::from_utf8_lossy(&response);
        let status_line = response.lines().next().unwrap_or_default();
        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse::<u16>().ok())
            .unwrap_or(0);
        if (200..300).contains(&status_code) {
            return Ok(());
        }
        let hint = match status_code {
            407 => " (proxy requires authentication)",
            403 => " (proxy refused the connection)",
            _ => "",
        };
        anyhow::bail!(
            "http proxy CONNECT to {target_authority} failed: {status_line}{hint}"
        );
    })
    .await
    .map_err(|elapsed| {
        anyhow::anyhow!(
            "http proxy CONNECT handshake timed out after {elapsed:?} to {target_authority}"
        )
    })?
}

use anyhow::Context;

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    #[test]
    fn proxy_config_requires_http_or_https_scheme() {
        assert!(HttpProxyConfig::new("socks5://127.0.0.1:1080".parse().unwrap()).is_err());
        assert!(HttpProxyConfig::new("http://127.0.0.1:8080".parse().unwrap()).is_ok());
        assert!(HttpProxyConfig::new("https://proxy.example:8443".parse().unwrap()).is_ok());
    }

    #[test]
    fn proxy_config_rejects_scheme_less_url() {
        assert!("127.0.0.1:8080".parse::<url::Url>().is_err());
    }

    #[test]
    fn proxy_config_parses_credentials() {
        let config =
            HttpProxyConfig::new("http://user:pass%40word@127.0.0.1:8080".parse().unwrap()).unwrap();
        let (username, password) = config.credentials().unwrap();
        assert_eq!(username, "user");
        assert_eq!(password, "pass@word");
        assert_eq!(
            config.authorization_header().unwrap(),
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode("user:pass@word")
            )
        );
    }

    #[test]
    fn proxy_config_rejects_missing_port() {
        assert!(HttpProxyConfig::new("http://127.0.0.1".parse().unwrap()).is_err());
    }

    #[test]
    fn formats_ipv6_authority() {
        assert_eq!(format_authority("::1", 8080), "[::1]:8080");
        assert_eq!(format_authority("proxy.example.com", 8080), "proxy.example.com:8080");
    }

    #[tokio::test]
    async fn http_connect_succeeds_and_tunnels_data() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let target = "203.0.113.9:11010".parse::<SocketAddr>().unwrap();

        let proxy = Arc::new(
            HttpProxyConfig::new(
                format!("http://127.0.0.1:{}", proxy_addr.port())
                    .parse()
                    .unwrap(),
            )
            .unwrap(),
        );

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut header = Vec::new();
            let mut buffer = [0u8; 1024];
            loop {
                let read = socket.read(&mut buffer).await.unwrap();
                if read == 0 {
                    panic!("proxy connection closed early");
                }
                header.extend_from_slice(&buffer[..read]);
                if header.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&header);
            assert!(request.starts_with(&format!("CONNECT {target} HTTP/1.1\r\n")));
            assert!(request.contains("Host: 203.0.113.9:11010"));
            socket
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            let mut echoed = [0u8; 6];
            socket.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"hello!");
            socket.write_all(b"pong!").await.unwrap();
        });

        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        http_connect(&mut stream, target, &proxy).await.unwrap();

        stream.write_all(b"hello!").await.unwrap();
        let mut reply = [0u8; 5];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong!");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn http_connect_reports_proxy_rejection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let target = "203.0.113.9:11010".parse::<SocketAddr>().unwrap();
        let proxy = Arc::new(
            HttpProxyConfig::new(
                format!("http://127.0.0.1:{}", proxy_addr.port())
                    .parse()
                    .unwrap(),
            )
            .unwrap(),
        );

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 4096];
            let _ = socket.read(&mut buffer).await;
            socket
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await
                .unwrap();
        });

        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        let error = http_connect(&mut stream, target, &proxy).await.unwrap_err();
        assert!(error.to_string().contains("502 Bad Gateway"));
        server.await.unwrap();
    }
}