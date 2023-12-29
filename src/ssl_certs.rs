use crate::{DductCfg, Result};
use openssl::asn1::{Asn1Time, Asn1Integer};
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::x509::{X509, X509Builder, X509Name};
use openssl::x509::extension::{AuthorityKeyIdentifier, SubjectKeyIdentifier};
use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName};
use std::default::Default;
use std::fs::{self};
use std::path::PathBuf;
use tokio_native_tls::native_tls::Identity;

const CERTIFICATE_VERSION: i32 = 2;

const P12_NAME: &str = "dduct";
const SERVER_P12: &str = "server.p12";
const CLIENT_P12: &str = "client.p12";

#[derive(Default)]
pub struct SslCerts {
    cfg: DductCfg,

    ca_pkey: Option<PKey<Private>>,
    ca_cert: Option<X509>,

    server_pkey: Option<PKey<Private>>,
    server_cert: Option<X509>,
    server_p12: Option<Pkcs12>,

    client_pkey: Option<PKey<Private>>,
    client_cert: Option<X509>,
    client_p12: Option<Pkcs12>,
}

impl SslCerts {
    pub fn new(cfg: &DductCfg) -> Self {
        let cfg = cfg.to_owned();
        Self { cfg, ..Default::default() }
    }

    pub fn server_id(&self) -> Result<Identity> {
        let id = Identity::from_pkcs12(
            self.server_p12.as_ref().unwrap().to_der()?.as_slice(),
            self.cfg.p12_pass.as_str(),
        )?;
        Ok(id)
    }

    pub fn client_id(&self) -> Result<Identity> {
        let id = Identity::from_pkcs12(
            self.client_p12.as_ref().unwrap().to_der()?.as_slice(),
            self.cfg.p12_pass.as_str(),
        )?;
        Ok(id)
    }

    fn new_serial_number() -> Result<Asn1Integer> {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        Ok(serial.to_asn1_integer()?)
    }

    fn ensure_pkey<F: Fn() -> Result<PKey<Private>>>(
        maybe_pkey: &mut Option<PKey<Private>>,
        path: &PathBuf,
        generate: F,
    ) -> Result<()> {
        if path.exists() {
            log::info!("Read {:?}", path);
            let contents = fs::read(path)?;
            *maybe_pkey = Some(
                PKey::from_rsa(
                    Rsa::private_key_from_pem(contents.as_slice())?,
                )?,
            );
        }
        if let None = maybe_pkey {
            *maybe_pkey = Some(
                generate()?,
            );
        }
        if !path.exists() {
            let contents = maybe_pkey.as_ref().unwrap().rsa()?.private_key_to_pem()?;
            log::info!("Write {:?}", path);
            fs::write(path, contents)?;
        }
        Ok(())
    }

    fn ensure_cert<F: Fn() -> Result<X509>>(
        maybe_cert: &mut Option<X509>,
        path: &PathBuf,
        generate: F,
    ) -> Result<()> {
        if path.exists() {
            log::info!("Read {:?}", path);
            let contents = fs::read(path)?;
            *maybe_cert = Some(
                X509::from_pem(contents.as_slice())?,
            );
        }
        if let None = maybe_cert {
            *maybe_cert = Some(
                generate()?,
            );
        }
        if !path.exists() {
            let contents = maybe_cert.as_ref().unwrap().to_pem()?;
            log::info!("Write {:?}", path);
            fs::write(path, contents)?;
        }
        Ok(())
    }

    fn ensure_p12<F: Fn() -> Result<Pkcs12>>(
        maybe_p12: &mut Option<Pkcs12>,
        path: &PathBuf,
        generate: F,
    ) -> Result<()> {
        if path.exists() {
            log::info!("Read {:?}", path);
            let contents = fs::read(path)?;
            *maybe_p12 = Some(
                Pkcs12::from_der(contents.as_slice())?,
            );
        }
        if let None = maybe_p12 {
            *maybe_p12 = Some(
                generate()?,
            );
        }
        if !path.exists() {
            let contents = maybe_p12.as_ref().unwrap().to_der()?;
            log::info!("Write {:?}", path);
            fs::write(path, contents)?;
        }
        Ok(())
    }

    fn ensure_ca_pkey(&mut self) -> Result<()> {
        let path = self.cfg.cert_dir.join("ca.key");
        let rsa_key_bits = self.cfg.rsa_key_bits;
        Self::ensure_pkey(&mut self.ca_pkey, &path, || {
            Ok(PKey::from_rsa(Rsa::generate(rsa_key_bits)?)?)
        })
    }

    fn append_ca_extensions(builder: &mut X509Builder) -> Result<()> {
        let ext = BasicConstraints::new()
            .critical()
            .ca()
            .build()?;
        builder.append_extension(ext)?;

        let ext = KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?;
        builder.append_extension(ext)?;

        let context = builder.x509v3_context(None, None);
        let ext = SubjectKeyIdentifier::new()
            .build(&context)?;
        builder.append_extension(ext)?;

        Ok(())
    }

    fn ensure_ca_cert(&mut self) -> Result<()> {
        let days_from_now = self.cfg.days_from_now;
        let ca_cn = self.cfg.ca_cn.to_owned();
        let path = self.cfg.cert_dir.join("ca.crt");
        let pkey = self.ca_pkey.to_owned().unwrap();
        Self::ensure_cert(&mut self.ca_cert, &path, || {
            let not_before = Asn1Time::days_from_now(0)?;
            let not_after = Asn1Time::days_from_now(days_from_now)?;

            let mut subject_name = X509Name::builder()?;
            subject_name.append_entry_by_nid(Nid::COMMONNAME, ca_cn.as_str())?;
            let subject_name = subject_name.build();

            let mut cert = X509::builder()?;
            cert.set_version(CERTIFICATE_VERSION)?;
            cert.set_serial_number(Self::new_serial_number()?.as_ref())?;
            cert.set_pubkey(&pkey)?;
            cert.set_not_before(&not_before)?;
            cert.set_not_after(&not_after)?;
            cert.set_subject_name(&subject_name)?;
            cert.set_issuer_name(&subject_name)?;
            Self::append_ca_extensions(&mut cert)?;
            cert.sign(&pkey, MessageDigest::sha256())?;  // self-signed
            let cert = cert.build();
            Ok(cert)
        })
    }

    fn ensure_server_pkey(&mut self) -> Result<()> {
        let rsa_key_bits = self.cfg.rsa_key_bits;
        let path = self.cfg.cert_dir.join("server.key");
        Self::ensure_pkey(&mut self.server_pkey, &path, || {
            Ok(PKey::from_rsa(Rsa::generate(rsa_key_bits)?)?)
        })
    }

    fn append_server_extensions(
        builder: &mut X509Builder,
        issuer: &X509,
        maybe_dns_sans: Option<Vec<String>>,
        maybe_ip_sans: Option<Vec<String>>,
    ) -> Result<()> {
        let context = builder.x509v3_context(Some(issuer), None);
        let ext = AuthorityKeyIdentifier::new()
            .keyid(true)
            .issuer(true)
            .build(&context)?;
        builder.append_extension(ext)?;

        let ext = BasicConstraints::new()
            .critical()
            .build()?;
        builder.append_extension(ext)?;

        let ext = ExtendedKeyUsage::new()
            .critical()
            .client_auth()
            .code_signing()
            .server_auth()
            .build()?;
        builder.append_extension(ext)?;

        let ext = KeyUsage::new()
            .critical()
            .data_encipherment()
            .digital_signature()
            .key_encipherment()
            .non_repudiation()
            .build()?;
        builder.append_extension(ext)?;

        let context = builder.x509v3_context(Some(issuer), None);
        let mut sans = SubjectAlternativeName::new();
        if let Some(dns_sans) = maybe_dns_sans {
            for san in dns_sans { sans.dns(san.as_str()); }
        }
        if let Some(ip_sans) = maybe_ip_sans {
            for san in ip_sans { sans.ip(san.as_str()); }
        }
        let ext = sans.build(&context)?;
        builder.append_extension(ext)?;

        Ok(())
    }

    fn ensure_server_cert(&mut self) -> Result<()> {
        let days_from_now = self.cfg.days_from_now;
        let server_cn = self.cfg.server_cn.to_owned();
        let server_dns_sans = self.cfg.server_dns_sans.to_vec();
        let server_ip_sans = self.cfg.server_ip_sans.to_vec();
        let path = self.cfg.cert_dir.join("server.crt");
        let pkey = self.server_pkey.to_owned().unwrap();
        let ca_cert = self.ca_cert.to_owned().unwrap();
        let ca_pkey = self.ca_pkey.to_owned().unwrap();
        Self::ensure_cert(&mut self.server_cert, &path, || {
            let not_before = Asn1Time::days_from_now(0)?;
            let not_after = Asn1Time::days_from_now(days_from_now)?;

            let mut subject_name = X509Name::builder()?;
            subject_name.append_entry_by_nid(Nid::COMMONNAME, server_cn.as_str())?;
            let subject_name = subject_name.build();

            let mut cert = X509::builder()?;
            cert.set_version(CERTIFICATE_VERSION)?;
            cert.set_serial_number(Self::new_serial_number()?.as_ref())?;
            cert.set_pubkey(&pkey)?;
            cert.set_not_before(&not_before)?;
            cert.set_not_after(&not_after)?;
            cert.set_subject_name(&subject_name)?;
            Self::append_server_extensions(&mut cert, &ca_cert, Some(server_dns_sans.to_owned()),
                                                                Some(server_ip_sans.to_owned()))?;
            cert.sign(&ca_pkey, MessageDigest::sha256())?;
            let cert = cert.build();
            Ok(cert)
        })
    }

    fn ensure_server_p12(&mut self) -> Result<()> {
        let p12_pass = self.cfg.p12_pass.to_owned();
        let path = self.cfg.cert_dir.join(SERVER_P12);
        let pkey = self.server_pkey.to_owned().unwrap();
        let cert = self.server_cert.to_owned().unwrap();
        let ca_cert = self.ca_cert.to_owned().unwrap();
        Self::ensure_p12(&mut self.server_p12, &path, || {
            let mut ca = Stack::new()?;
            ca.push(ca_cert.to_owned())?;
            let mut p12 = Pkcs12::builder();
            p12.ca(ca);
            p12.name(P12_NAME);
            p12.pkey(&pkey);
            p12.cert(&cert);
            let p12 = p12.build2(p12_pass.as_str())?;
            Ok(p12)
        })
    }

    fn ensure_client_pkey(&mut self) -> Result<()> {
        let rsa_key_bits = self.cfg.rsa_key_bits;
        let path = self.cfg.cert_dir.join("client.key");
        Self::ensure_pkey(&mut self.client_pkey, &path, || {
            Ok(PKey::from_rsa(Rsa::generate(rsa_key_bits)?)?)
        })
    }

    fn ensure_client_cert(&mut self) -> Result<()> {
        let days_from_now = self.cfg.days_from_now;
        let client_cn = self.cfg.client_cn.to_owned();
        let path = self.cfg.cert_dir.join("client.crt");
        let pkey = self.client_pkey.to_owned().unwrap();
        let ca_cert = self.ca_cert.to_owned().unwrap();
        let ca_pkey = self.ca_pkey.to_owned().unwrap();
        Self::ensure_cert(&mut self.client_cert, &path, || {
            let not_before = Asn1Time::days_from_now(0)?;
            let not_after = Asn1Time::days_from_now(days_from_now)?;

            let mut subject_name = X509Name::builder()?;
            subject_name.append_entry_by_nid(Nid::COMMONNAME, client_cn.as_str())?;
            let subject_name = subject_name.build();

            let mut cert = X509::builder()?;
            cert.set_version(CERTIFICATE_VERSION)?;
            cert.set_serial_number(Self::new_serial_number()?.as_ref())?;
            cert.set_pubkey(&pkey)?;
            cert.set_not_before(&not_before)?;
            cert.set_not_after(&not_after)?;
            cert.set_subject_name(&subject_name)?;
            Self::append_server_extensions(&mut cert, &ca_cert, None,
                                                                None)?;
            cert.sign(&ca_pkey, MessageDigest::sha256())?;
            let cert = cert.build();
            Ok(cert)
        })
    }

    fn ensure_client_p12(&mut self) -> Result<()> {
        let p12_pass = self.cfg.p12_pass.to_owned();
        let path = self.cfg.cert_dir.join(CLIENT_P12);
        let pkey = self.client_pkey.to_owned().unwrap();
        let cert = self.client_cert.to_owned().unwrap();
        let ca_cert = self.ca_cert.to_owned().unwrap();
        Self::ensure_p12(&mut self.client_p12, &path, || {
            let mut ca = Stack::new()?;
            ca.push(ca_cert.to_owned())?;
            let mut p12 = Pkcs12::builder();
            p12.ca(ca);
            p12.name(P12_NAME);
            p12.pkey(&pkey);
            p12.cert(&cert);
            let p12 = p12.build2(p12_pass.as_str())?;
            Ok(p12)
        })
    }

    pub fn generate(&mut self) -> Result<()> {
        self.ensure_ca_pkey()?;
        self.ensure_ca_cert()?;

        self.ensure_server_pkey()?;
        self.ensure_server_cert()?;
        self.ensure_server_p12()?;

        self.ensure_client_pkey()?;
        self.ensure_client_cert()?;
        self.ensure_client_p12()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() {
        env_logger::try_init_from_env(
            env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "debug")).ok();
    }

    #[test]
    fn test_ssl_certs() -> Result<()> {
        setup();

        let dir = tempdir::TempDir::new("dduct")?;
        let cfg = DductCfg { cert_dir: dir.path().into(), ..Default::default() };

        let mut ssl_certs = SslCerts::new(&cfg);
        ssl_certs.generate()?;
        ssl_certs.server_id()?;
        ssl_certs.client_id()?;

        let mut ssl_certs = SslCerts::new(&cfg);
        ssl_certs.generate()?;
        ssl_certs.server_id()?;
        ssl_certs.client_id()?;

        Ok(())
    }
}
