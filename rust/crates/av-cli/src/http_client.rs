//! A small HTTP/1.1 client over a Unix socket or TCP. The CLI is a thin
//! client of the daemon; this is the transport `control` and the MCP bridge
//! use. No new HTTP crate: the approved list does not add one for this.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// One response. Header lookup keeps the first value of a name, matching
/// "only the first Authorization header counts" when a caller asks.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// Status code.
    pub status: u16,
    /// Header names as received, values trimmed.
    pub headers: Vec<(String, String)>,
    /// Body bytes.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// The first header with this name, case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The body as a lossy UTF-8 string.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// `GET`/`POST` on a Unix socket. `Connection: close`; the body is read to
/// EOF, honoring `Content-Length` and chunked transfer.
pub fn request_unix(
    socket: &Path,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    extra: &[(&str, &str)],
) -> std::io::Result<HttpResponse> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(120)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    exchange(&mut stream, method, path, "localhost", body, extra)
}

/// The same request over TCP (`127.0.0.1` for the gateway and MCP).
pub fn request_tcp(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    extra: &[(&str, &str)],
) -> std::io::Result<HttpResponse> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(120)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    exchange(&mut stream, method, path, "127.0.0.1", body, extra)
}

fn exchange(
    stream: &mut impl ReadWrite,
    method: &str,
    path: &str,
    host: &str,
    body: Option<&[u8]>,
    extra: &[(&str, &str)],
) -> std::io::Result<HttpResponse> {
    let body = body.unwrap_or(b"");
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if !body.is_empty() {
        req.push_str("Content-Type: application/json\r\n");
    }
    for (k, v) in extra {
        // No CR/LF in a header we ourselves build.
        if k.bytes().any(|c| c == b'\r' || c == b'\n')
            || v.bytes().any(|c| c == b'\r' || c == b'\n')
        {
            continue;
        }
        req.push_str(k);
        req.push_str(": ");
        req.push_str(v);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes())?;
    if !body.is_empty() {
        stream.write_all(body)?;
    }
    stream.flush()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    parse_response(&raw)
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn parse_response(raw: &[u8]) -> std::io::Result<HttpResponse> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "short HTTP response")
        })?;
    let head = String::from_utf8_lossy(&raw[..sep]);
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let mut body = raw[sep + 4..].to_vec();
    let chunked = headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked")
    });
    if chunked {
        body = decode_chunked(&body)?;
    } else if let Some(n) = headers.iter().find_map(|(k, v)| {
        k.eq_ignore_ascii_case("content-length")
            .then(|| v.parse::<usize>().ok())
            .flatten()
    }) {
        if body.len() > n {
            body.truncate(n);
        }
    }
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

fn decode_chunked(mut data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = data
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad chunk"))?;
        let len_txt = std::str::from_utf8(&data[..line_end]).unwrap_or("");
        let len = usize::from_str_radix(len_txt.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad chunk size"))?;
        data = &data[line_end + 2..];
        if len == 0 {
            break;
        }
        if data.len() < len + 2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "short chunk",
            ));
        }
        out.extend_from_slice(&data[..len]);
        data = &data[len + 2..];
    }
    Ok(out)
}
