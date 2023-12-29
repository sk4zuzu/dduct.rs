use crate::Result;
use clap::Parser;
use serde::Deserialize;
use std::convert::identity;
use std::default::Default;
use std::env::current_exe;
use std::fs::{self};
use std::net::SocketAddr;
use std::path::PathBuf;
use toml::{self};

macro_rules! get_exe_dir {
    () => { current_exe().unwrap().parent().unwrap().to_path_buf() };
}

#[derive(Debug, Parser)]
#[command(version)]
struct Args {
    #[arg(short, long, value_name = "FILE")]
    cfg: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct DductArgs {
    pub cfg_path: PathBuf,
}

impl Default for DductArgs {
    fn default() -> Self {
        let parent_dir = get_exe_dir!();
        Self { cfg_path: parent_dir.join("dduct.toml") }
    }
}

pub fn parse_args() -> Result<DductArgs> {
    let parsed = Args::parse();

    let mut args = DductArgs { ..Default::default() };

    macro_rules! resolve {
        ($dst:ident, $src:ident) => { args.$dst = parsed.$src.to_owned().map_or(args.$dst, identity) };
    }

    resolve!(cfg_path, cfg);

    Ok(args)
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct Cfg {
    misc: Option<CfgMisc>,
    proxy: Option<CfgProxy>,
    certs: Option<CfgCerts>,
}

impl Default for Cfg {
    fn default() -> Self {
        Self {
            misc: Some(CfgMisc { ..Default::default() }),
            proxy: Some(CfgProxy { ..Default::default() }),
            certs: Some(CfgCerts { ..Default::default() }),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct CfgMisc {
    log_level: Option<String>,
    cert_dir: Option<PathBuf>,
    file_dir: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
struct CfgProxy {
    tcp_bind: Option<SocketAddr>,
    tls_bind: Option<SocketAddr>,
}

#[derive(Debug, Default, Deserialize)]
struct CfgCerts {
    rsa_key_bits: Option<u32>,
    days_from_now: Option<u32>,
    ca_cn: Option<String>,
    server_cn: Option<String>,
    server_dns_sans: Option<Vec<String>>,
    server_ip_sans: Option<Vec<String>>,
    client_cn: Option<String>,
    p12_pass: Option<String>,
}

#[derive(Clone, Debug)]
pub struct DductCfg {
    pub log_level: String,
    pub cert_dir: PathBuf,
    pub file_dir: PathBuf,

    pub tcp_bind: SocketAddr,
    pub tls_bind: SocketAddr,

    pub rsa_key_bits: u32,
    pub days_from_now: u32,
    pub ca_cn: String,
    pub server_cn: String,
    pub server_dns_sans: Vec<String>,
    pub server_ip_sans: Vec<String>,
    pub client_cn: String,
    pub p12_pass: String,
}

impl Default for DductCfg {
    fn default() -> Self {
        let parent_dir = get_exe_dir!();
        Self {
            log_level: "info".into(),
            cert_dir: parent_dir.join("certs"),
            file_dir: parent_dir.join("files"),

            tcp_bind: ([127, 0, 0, 1], 8000).into(),
            tls_bind: ([0, 0, 0, 0], 4430).into(),

            rsa_key_bits: 3072,
            days_from_now: 3072,
            ca_cn: "dduct".into(),
            server_cn: "*.dduct.lh".into(),
            server_dns_sans: vec!["*.dduct.rs".into(), "*.docker.io".into()],
            server_ip_sans: vec!["127.0.0.1".into()],
            client_cn: "*.dduct.lh".into(),
            p12_pass: "dduct".into(),
        }
    }
}

pub fn parse_cfg(args: &DductArgs) -> Result<DductCfg> {
    if !args.cfg_path.exists() {
        return Ok(DductCfg { ..Default::default() });
    }

    let contents = fs::read(args.cfg_path.as_path())?;
    let contents = unsafe { String::from_utf8_unchecked(contents) };

    let parsed: Cfg = toml::from_str(contents.as_str())?;

    let mut cfg = DductCfg { ..Default::default() };

    macro_rules! resolve {
        ($sub:ident, $dst:ident, $src:ident) => { cfg.$dst = $sub.$src.to_owned().map_or(cfg.$dst, identity) };
    }

    let misc = parsed.misc.as_ref().unwrap();
    resolve!(misc, log_level, log_level);
    resolve!(misc, cert_dir, cert_dir);
    resolve!(misc, file_dir, file_dir);

    let proxy = parsed.proxy.as_ref().unwrap();
    resolve!(proxy, tcp_bind, tcp_bind);
    resolve!(proxy, tls_bind, tls_bind);

    let certs = parsed.certs.as_ref().unwrap();
    resolve!(certs, rsa_key_bits, rsa_key_bits);
    resolve!(certs, days_from_now, days_from_now);
    resolve!(certs, ca_cn, ca_cn);
    resolve!(certs, server_cn, server_cn);
    resolve!(certs, server_dns_sans, server_dns_sans);
    resolve!(certs, server_ip_sans, server_ip_sans);
    resolve!(certs, client_cn, client_cn);
    resolve!(certs, p12_pass, p12_pass);

    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() {
        env_logger::try_init_from_env(
            env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "debug")).ok();
    }

    #[test]
    fn test_parse_cfg() -> Result<()> {
        setup();

        let dir = tempdir::TempDir::new("dduct")?;

        let args = DductArgs { cfg_path: dir.path().join("dduct.toml"), ..Default::default() };

        fs::write(args.cfg_path.as_path(), indoc::indoc! {r#"
            [misc]
            log_level = "debug"
            cert_dir = "/var/tmp/dduct/certs/"
            #file_dir = "/var/tmp/dduct/files/"
            [proxy]
            #tcp_bind = "127.0.0.1:8000"
            tls_bind = "1.2.3.4:1234"
            #[certs]
            #rsa_key_bits = 3072
            #server_ip_sans = ["127.0.0.1"]
            p12_pass = "asd"
        "#})?;

        let cfg = parse_cfg(&args)?;

        assert_eq!(cfg.log_level, "debug");
        assert_eq!(cfg.cert_dir, PathBuf::from("/var/tmp/dduct/certs/"));
        assert_eq!(cfg.file_dir, get_exe_dir!().join("files")); // default

        assert_eq!(cfg.tcp_bind, ([127, 0, 0, 1], 8000).into()); // default
        assert_eq!(cfg.tls_bind, ([1, 2, 3, 4], 1234).into());

        assert_eq!(cfg.rsa_key_bits, 3072); // default
        assert_eq!(cfg.server_ip_sans, vec!["127.0.0.1".to_string()]); // default
        assert_eq!(cfg.p12_pass, "dduct"); // default (missing [certs] section in toml)

        Ok(())
    }
}
