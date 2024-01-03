use crate::{DductCfg, FileOpener, HttpProxy, Result, SslCerts, TlsMitm};
use futures::future::{self};

pub async fn serve(cfg: &DductCfg, ssl_certs: &SslCerts) -> Result<()> {
    log::info!("Files {:?}", cfg.file_dir.as_path());

    let file_opener = FileOpener::new(
        cfg.file_dir.as_path(),
        Some(cfg.filters.to_owned()),
    );

    future::try_join(
        HttpProxy::new(
            cfg.tcp_bind,
            cfg.tls_bind,
            ssl_certs,
            &file_opener,
        ).serve(),
        TlsMitm::new(
            cfg.tls_bind,
            ssl_certs,
            &file_opener,
        ).serve(),
    ).await?;

    Ok(())
}
