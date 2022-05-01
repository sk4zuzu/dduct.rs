use crate::{DductError, Request, Response, Result};
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http::version::Version;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};

const VEC_CAPACITY: usize = 4*1024;

enum Line {
    Done,
    Skip,
    Some(Vec<u8>),
    Body(Vec<u8>),
}

pub struct HttpParser<R> {
    buffer: Vec<u8>,
    reader: BufReader<R>,
    skipped: bool,
}

impl<R> HttpParser<R> where R: AsyncRead + Unpin {
    pub fn new(reader: R) -> Self {
        Self {
            buffer: Vec::with_capacity(VEC_CAPACITY),
            reader: BufReader::new(reader),
            skipped: false,
        }
    }

    pub fn reset(mut self) {
        self.buffer.clear();
        self.reader = BufReader::new(self.reader.into_inner());
        self.skipped = false;
    }

    async fn maybe_next_line(&mut self) -> Result<Line> {
        let n = self.reader.read_until(b'\n', &mut self.buffer).await?;
        if n == 0 {
            Ok(Line::Done)
        } else {
            let slice = self.buffer.as_slice();
            let mut maybe_line = &slice[(slice.len() - n)..];  // can become "empty" after trim

            if let Some(b'\n') = maybe_line.last() {
                maybe_line = &maybe_line[..(maybe_line.len() - 1)];
            }
            if let Some(b'\r') = maybe_line.last() {
                maybe_line = &maybe_line[..(maybe_line.len() - 1)];
            }

            if maybe_line.is_empty() {
                if self.skipped {
                    Ok(Line::Body(self.reader.buffer().to_vec()))
                } else {
                    Ok(Line::Skip)
                }
            } else {
                self.skipped = true;
                Ok(Line::Some(maybe_line.to_vec()))
            }
        }
    }

    async fn skip_empty_lines(&mut self) -> Result<Line> {
        loop {
            let maybe_line = self.maybe_next_line().await?;
            if let Line::Skip = maybe_line {
                continue;
            } else {
                return Ok(maybe_line);
            }
        }
    }

    fn parse_version(maybe_version: &str) -> Version {
        match maybe_version.to_uppercase().trim() {
            "HTTP/0.9" => Version::HTTP_09,
            "HTTP/1.0" => Version::HTTP_10,
            "HTTP/2.0" => Version::HTTP_2,
            "HTTP/3.0" => Version::HTTP_3,
            _ => Version::HTTP_11,
        }
    }

    async fn parse_headers(&mut self, headers: &mut HeaderMap<HeaderValue>) -> Result<Line> {
        loop {
            let maybe_line = self.maybe_next_line().await?;
            if let Line::Some(line) = maybe_line {
                let line = unsafe { String::from_utf8_unchecked(line) };

                let parts: Vec<&str> = line
                    .split(":")
                    .map(|part| part.trim())
                    .collect();

                let (name, value) = (
                    parts[0],
                    parts[1..].join(":"),
                );

                headers.insert(
                    HeaderName::from_bytes(name.as_bytes())
                        .map_err(|_| DductError::BadRequest)?,
                    HeaderValue::from_bytes(value.as_bytes())
                        .map_err(|_| DductError::BadRequest)?,
                );
            } else {
                return Ok(maybe_line);
            }
        }
    }

    pub async fn parse_request(&mut self) -> Result<Option<Request>> {
        let mut builder = http::Request::builder();

        match self.skip_empty_lines().await? {
            Line::Done => return Ok(None),
            Line::Skip => unreachable!(),
            Line::Some(line) => {
                let line = unsafe { String::from_utf8_unchecked(line) };

                let parts: Vec<&str> = line
                    .split(" ")
                    .map(|part| part.trim())
                    .filter(|part| !part.is_empty())
                    .collect();

                let parts_len = parts.len();

                if parts_len >= 1 {
                    builder = builder.method(parts[0]);
                }
                if parts_len >= 2 {
                    builder = builder.uri(parts[1]);
                }
                if parts_len >= 3 {
                    builder = builder.version(Self::parse_version(parts[2]));
                }
            },
            Line::Body(_) => unreachable!(),
        }

        match self.parse_headers(builder.headers_mut().unwrap()).await? {
            Line::Done => return Ok(Some(builder.body(None)?)),
            Line::Skip => unreachable!(),
            Line::Some(_) => unreachable!(),
            Line::Body(body) => return Ok(Some(builder.body(Some(body))?)),
        }
    }

    pub async fn parse_response(&mut self) -> Result<Option<Response>> {
        let mut builder = http::Response::builder();

        match self.skip_empty_lines().await? {
            Line::Done => return Ok(None),
            Line::Skip => unreachable!(),
            Line::Some(line) => {
                let line = unsafe { String::from_utf8_unchecked(line) };

                let parts: Vec<&str> = line.split(" ")
                    .map(|part| part.trim())
                    .filter(|part| !part.is_empty())
                    .collect();

                let parts_len = parts.len();

                if parts_len >= 1 {
                    builder = builder.version(Self::parse_version(parts[0]));
                }
                if parts_len >= 2 {
                    builder = builder.status(parts[1]);
                }
            },
            Line::Body(_) => unreachable!(),
        }

        match self.parse_headers(builder.headers_mut().unwrap()).await? {
            Line::Done => return Ok(Some(builder.body(None)?)),
            Line::Skip => unreachable!(),
            Line::Some(_) => unreachable!(),
            Line::Body(body) => return Ok(Some(builder.body(Some(body))?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use http::header::{self};
    use http::method::Method;
    use http::status::StatusCode;
    use tokio::io::{self};
    use tokio_stream as stream;
    use tokio_util::io::StreamReader;

    fn setup() {
        env_logger::try_init_from_env(
            env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "debug")).ok();
    }

    #[tokio::test]
    async fn test_parse_request() -> Result<()> {
        setup();

        let stream = stream::iter(vec![
            /*  7 */ io::Result::Ok(&b"\n\n\r\n\n\r\n"[..]),
            /*  5 */ io::Result::Ok(&b"GET /"[..]),
            /* 15 */ io::Result::Ok(&b"path HTTP/2.0\r\n"[..]),
            /*  6 */ io::Result::Ok(&b"Host: "[..]),
            /* 16 */ io::Result::Ok(&b"127.0.0.1:8000\r\n"[..]),
            /* 13 */ io::Result::Ok(&b"Accept: */*\r\n"[..]),
            /*  8 */ io::Result::Ok(&b"\r\nbody.."[..]),
        ]);

        let reader = StreamReader::new(stream);
        let mut parser = HttpParser::new(reader);

        let req = parser.parse_request().await?.unwrap();
        parser.reset();

        assert_eq!(req.method(), Method::GET);
        assert_eq!(req.uri().path(), "/path");
        assert_eq!(req.version(), Version::HTTP_2);

        assert_eq!(req.headers()[header::HOST], "127.0.0.1:8000");
        assert_eq!(req.headers()[header::ACCEPT], "*/*");

        assert_eq!(*req.body(), Some("body..".into()));

        Ok(())
    }

    #[tokio::test]
    async fn test_parse_response() -> Result<()> {
        setup();

        let stream = stream::iter(vec![
            /*  7 */ io::Result::Ok(&b"\n\n\r\n\n\r\n"[..]),
            /*  2 */ io::Result::Ok(&b"HT"[..]),
            /* 15 */ io::Result::Ok(&b"TP/2.0 200 OK\r\n"[..]),
            /*  6 */ io::Result::Ok(&b"Host: "[..]),
            /* 16 */ io::Result::Ok(&b"127.0.0.1:8000\r\n"[..]),
            /* 13 */ io::Result::Ok(&b"Accept: */*\r\n"[..]),
            /*  8 */ io::Result::Ok(&b"\r\nbody.."[..]),
        ]);

        let reader = StreamReader::new(stream);
        let mut parser = HttpParser::new(reader);

        let req = parser.parse_response().await?.unwrap();
        parser.reset();

        assert_eq!(req.version(), Version::HTTP_2);
        assert_eq!(req.status(), StatusCode::OK);

        assert_eq!(req.headers()[header::HOST], "127.0.0.1:8000");
        assert_eq!(req.headers()[header::ACCEPT], "*/*");

        assert_eq!(*req.body(), Some("body..".into()));

        Ok(())
    }
}
