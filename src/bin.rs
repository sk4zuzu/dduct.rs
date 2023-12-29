use dduct::{DductCfg, Result, SslCerts, parse_args, parse_cfg, serve};
use std::fs::create_dir_all;

fn ensure_dirs(cfg: &DductCfg) -> Result<()> {
    if !cfg.cert_dir.exists() {
        create_dir_all(cfg.cert_dir.as_path())?;
    }
    if !cfg.file_dir.exists() {
        create_dir_all(cfg.file_dir.as_path())?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;

    let cfg = parse_cfg(&args)?;

    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, cfg.log_level.clone()));

    ensure_dirs(&cfg)?;

    let mut ssl_certs = SslCerts::new(&cfg);
    ssl_certs.generate()?;

    serve(&cfg, &ssl_certs).await
}
