use thiserror::Error;

#[derive(Debug, Error)]
pub enum DductError {
    #[error("Bad request")]
    BadRequest,

    #[error(transparent)]
    Http(#[from] http::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Ssl(#[from] openssl::error::ErrorStack),

    #[error(transparent)]
    Tls(#[from] tokio_native_tls::native_tls::Error),
}

pub type Result<T> = std::result::Result<T, DductError>;
