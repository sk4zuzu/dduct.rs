[//]: # ( vim: set wrap : )

DDUCT, MITM HTTP(S) PROXY
=========================

<p align="center">
  <img src="https://avatars.githubusercontent.com/u/6539663" alt="Dduct"/>
</p>

## 1. PURPOSE

This is an experimental tool to reduce network utilization in multi container / VM environments like Kubernetes or OpenNebula clusters.

It's really a HTTP(S) proxy server that transparently caches binary files (like Docker / OCI image layers or compressed .txz archives) in your local filesystem, and then distributes them for any subsequent request. Effectively each binary file is downloaded only once and then cached forever.

> [!NOTE]
> It's probably not something you'd use in production clusters, but at least it can actually be utilized in busy integration / test environments (with lots of Docker builds / deployments or Apt / Yum upgrades).

## 2. PROBLEM

Almost everything runs now on HTTPS, so it's not possible to eavesdrop all that traffic and collect binary data for caching. Even when a HTTP(S) proxy is used, HTTPS connections are end-to-end encrypted and clients talk directly to servers through blind TCP conduits.

So you can either host and manage your own package repositories / Docker registries, or try a man-in-the-middle attack. :thinking:

## 3. SOLUTION?

Since you don't own private keys of various Docker registries and package repositories, you can only fake them instead on client's and proxy's sides, re-encrypt the stream, and selectively cache binary data on-the-fly.

Dduct assumes your HTTP(S) clients use HTTP(S) proxy, the HTTP CONNECT method, which creates a direct TCP conduit, but it's redirected to a fake / local HTTPS endpoint.

> [!NOTE]
> A fake Certificate Authority is used to generate server keys and certificates, and at least the main CA certificate needs to be distributed among all clients.

## 4. USAGE

You can build Dduct normally using local Cargo or statically (Musl) in Docker / Podman.

In NixOS:

```shell
$ nix-shell
$ make build # or "make b"
```

Statically:

```shell
$ make static # or "make s"
```

Dduct supports Toml configuration, a full config example looks like this:

```toml
[misc]
log_level = 'info'
cert_dir  = '/var/tmp/dduct/certs/'
file_dir  = '/var/tmp/dduct/files/'

[proxy]
tcp_bind = '127.0.0.1:8000'
tls_bind = '0.0.0.0:4430'
filters  = [
  '^/v2/.*/blobs/sha256:\w+$',
  '^/.*\.(?:apk|deb|rpm)$',
  '^/.*\.(?:tar|tbz|tgz|txz)$',
  '^/.*\.(?:7z|bz2|gz|xz|zip|zst)$',
]

[certs]
rsa_key_bits    = 3072
days_from_now   = 3072
ca_cn           = 'dduct'
server_cn       = '*.dduct.rs'
server_dns_sans = [
  '*.dduct.rs',
  '*.docker.io',
  '*.gcr.io',
  '*.githubusercontent.com',
  '*.k8s.io',
  '*.quay.io',
  'ghcr.io',
  'quay.io',
]
server_ip_sans  = ['127.0.0.1']
client_cn       = 'client.dduct.rs'
p12_pass        = 'dduct'
```

You can create the config file anywhere in your filesystem and run the binary like this:

```shell
$ ./dduct --cfg /var/tmp/dduct/dduct.toml
[2024-01-01T12:34:56Z INFO  dduct::ssl_certs] Write "/var/tmp/dduct/certs/ca.key"
[2024-01-01T12:34:56Z INFO  dduct::ssl_certs] Write "/var/tmp/dduct/certs/ca.crt"
[2024-01-01T12:34:56Z INFO  dduct::ssl_certs] Write "/var/tmp/dduct/certs/server.key"
[2024-01-01T12:34:56Z INFO  dduct::ssl_certs] Write "/var/tmp/dduct/certs/server.crt"
[2024-01-01T12:34:56Z INFO  dduct::ssl_certs] Write "/var/tmp/dduct/certs/server.p12"
[2024-01-01T12:34:56Z INFO  dduct::ssl_certs] Write "/var/tmp/dduct/certs/client.key"
[2024-01-01T12:34:56Z INFO  dduct::ssl_certs] Write "/var/tmp/dduct/certs/client.crt"
[2024-01-01T12:34:56Z INFO  dduct::ssl_certs] Write "/var/tmp/dduct/certs/client.p12"
[2024-01-01T12:34:56Z INFO  dduct::serve] Files "/var/tmp/dduct/files/"
[2024-01-01T12:34:56Z INFO  dduct::http_proxy] Listening on 127.0.0.1:8000
[2024-01-01T12:34:56Z INFO  dduct::tls_mitm] Listening on 0.0.0.0:4430
```

Or if the config file path is not specified from cli, you can put the config file next to `./dduct` binary.

Finally if both options are not used, Dduct starts with default values.

Looking at the listing above, `/var/tmp/dduct/certs/` directory contains the `ca.crt` file that needs to be propagated to each client's OS (installed with ca-certificates), to make TLS / SSL connections "green".

To simply test the proxy itself with curl:

```shell
$ curl -fv -x http://127.0.0.1:8000 --cacert /var/tmp/dduct/certs/ca.crt -LO https://some.thing/here.txz
```

Or fully encrypted:

```shell
$ curl -fv --proxy-cacert /var/tmp/dduct/certs/ca.crt -x https://127.0.0.1:4430 --cacert /var/tmp/dduct/certs/ca.crt -LO https://some.thing/here.txz
```

> [!NOTE]
> If you'd like to add more dns / ip SANs, then please delete `/var/tmp/dduct/certs/server.*` files and restart the proxy.

```shell
$ rm /var/tmp/dduct/certs/server.*
$ ./dduct --cfg /var/tmp/dduct/dduct.toml
[2024-01-01T12:34:56Z INFO  dduct::ssl_certs] Read "/var/tmp/dduct/certs/ca.key"
[2024-01-01T12:34:56Z INFO  dduct::ssl_certs] Read "/var/tmp/dduct/certs/ca.crt"
[2024-01-01T12:34:56Z INFO  dduct::ssl_certs] Write "/var/tmp/dduct/certs/server.key"
[2024-01-01T12:34:56Z INFO  dduct::ssl_certs] Write "/var/tmp/dduct/certs/server.crt"
[2024-01-01T12:34:56Z INFO  dduct::ssl_certs] Write "/var/tmp/dduct/certs/server.p12"
[2024-01-01T12:34:56Z INFO  dduct::ssl_certs] Read "/var/tmp/dduct/certs/client.key"
[2024-01-01T12:34:56Z INFO  dduct::ssl_certs] Read "/var/tmp/dduct/certs/client.crt"
[2024-01-01T12:34:56Z INFO  dduct::ssl_certs] Read "/var/tmp/dduct/certs/client.p12"
[2024-01-01T12:34:56Z INFO  dduct::serve] Files "/var/tmp/dduct/files/"
[2024-01-01T12:34:56Z INFO  dduct::http_proxy] Listening on 127.0.0.1:8000
[2024-01-01T12:34:56Z INFO  dduct::tls_mitm] Listening on 0.0.0.0:4430
```
