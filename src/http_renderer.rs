use crate::Result;

use http::header::{HeaderMap, HeaderValue};
use std::io::Write;

const VEC_CAPACITY: usize = 4*1024;

pub type Request = http::Request<Option<Vec<u8>>>;
pub type Response = http::Response<Option<Vec<u8>>>;

pub struct HttpRenderer;

impl HttpRenderer {
    fn render_headers(headers: &HeaderMap<HeaderValue>, output: &mut Vec<u8>) -> Result<()> {
        for (key, value) in headers {
            let key = key.as_str().split("-")
                .map(|item| {
                    let mut string = String::new();
                    string.push_str(&item[..1].to_uppercase());
                    string.push_str(&item[1..]);
                    string
                })
                .collect::<Vec<String>>()
                .join("-");

            write!(output, "{}: {}\r\n", key, value.to_str().unwrap())?;
        }
        Ok(())
    }

    pub fn render_request(request: &Request) -> Vec<u8> {
        let mut output = Vec::with_capacity(VEC_CAPACITY);

        write!(output, "{:?} {:?} {:?}\r\n", request.method(), request.uri(), request.version()).ok();

        Self::render_headers(request.headers(), &mut output).ok();

        if let Some(body) = request.body() {
            write!(output, "\r\n").ok();
            output.extend_from_slice(body.as_slice());
        }

        output
    }

    pub fn render_response(response: &Response) -> Vec<u8> {
        let mut output = Vec::with_capacity(VEC_CAPACITY);

        write!(output, "{:?} {:?}\r\n", response.version(), response.status()).ok();

        Self::render_headers(response.headers(), &mut output).ok();

        if let Some(body) = response.body() {
            write!(output, "\r\n").ok();
            output.extend_from_slice(body.as_slice());
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use http::header::{self};
    use http::method::Method;
    use http::status::StatusCode;
    use http::version::Version;

    fn setup() {
        env_logger::try_init_from_env(
            env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "debug")).ok();
    }

    #[test]
    fn test_render_request() {
        setup();

        let req = http::Request::builder()
            .method(Method::GET)
            .uri("/uri")
            .version(Version::HTTP_11)
            .header(header::HOST, "127.0.0.1:8000")
            .header(header::ACCEPT, "*/*")
            .body(Some("body..".into()))
            .unwrap();

        assert_eq!(
            HttpRenderer::render_request(&req),
            b"GET /uri HTTP/1.1\r\nHost: 127.0.0.1:8000\r\nAccept: */*\r\n\r\nbody..",
        )
    }

    #[test]
    fn test_render_response() {
        setup();

        let rsp = http::Response::builder()
            .version(Version::HTTP_11)
            .status(StatusCode::NOT_IMPLEMENTED)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(Some("body..".into()))
            .unwrap();

        assert_eq!(
            HttpRenderer::render_response(&rsp),
            b"HTTP/1.1 501\r\nContent-Type: application/octet-stream\r\n\r\nbody..",
        );
    }
}
