use crate::{DductError, Request, Result};
use http::header::{self};
use http::uri::{Scheme, Uri};
use nix::ifaddrs::getifaddrs;
use nix::sys::socket::{AddressFamily, SockaddrLike};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::net::lookup_host;

pub fn detect_ifaddrs() -> Result<HashSet<IpAddr>> {
    let mut addrs = HashSet::new();

    for ifaddr in getifaddrs()? {
        if let Some(addr) = ifaddr.address {
            match addr.family() {
                Some(AddressFamily::Inet) =>
                    if let Some(sa) = addr.as_sockaddr_in() {
                        addrs.insert(IpAddr::V4(Ipv4Addr::from(sa.ip())));
                    },
                Some(AddressFamily::Inet6) =>
                    if let Some(sa) = addr.as_sockaddr_in6() {
                        addrs.insert(IpAddr::V6(Ipv6Addr::from(sa.ip())));
                    },
                _ => (),
            }
        }
    }

    Ok(addrs)
}

pub async fn resolve_addr(req: &Request) -> Result<(SocketAddr, String)> {
    fn default_port(maybe_scheme: Option<&Scheme>) -> Result<u16> {
        if maybe_scheme == Some(&Scheme::HTTP) {
            return Ok(80);
        } else {
            return Ok(443);
        }
    }

    let (host, port): (String, u16) = match (req.uri().host(), req.uri().port_u16()) {
        (Some(h), Some(p)) => (h.into(), p),
        (Some(h), None) => (h.into(), default_port(req.uri().scheme())?),
        (_, _) => {
            let uri: Uri = req.headers()
                .get(header::HOST)
                .and_then(|h| h.to_str().ok())
                .ok_or(DductError::BadRequest)?
                .parse()
                .map_err(|_| DductError::BadRequest)?;
            match (uri.host(), uri.port_u16()) {
                (Some(h), Some(p)) => (h.into(), p),
                (Some(h), None) => (h.into(), default_port(req.uri().scheme())?),
                (_, _) => return Err(DductError::BadRequest),
            }
        },
    };

    Ok((
        lookup_host(format!("{}:{}", host, port)).await?.next().ok_or(DductError::BadRequest)?,
        host,
    ))
}
