# vim:ts=4:sw=4:noet:

SHELL := $(shell which bash)
SELF  := $(patsubst %/,%,$(dir $(abspath $(firstword $(MAKEFILE_LIST)))))

PACKAGE_NAME := dduct
PACKAGE_LIB  := lib$(PACKAGE_NAME)
PACKAGE_BIN  := $(PACKAGE_NAME)

RUST_LOG       := debug
RUST_BACKTRACE := full

OPENSSL_VERSION     := 3.2.0
DOCKER_DIND_VERSION := 24.0.7-alpine3.19
PODMAN_PINP_VERSION := v4.8.1

ARTIFACT1 ?= docker.io/library/ubuntu:22.04
ARTIFACT2 ?= https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.8.tar.xz

NO_CACHE ?=

_HTTP_PROXY_  := https://proxy.dduct.rs:4430
_HTTPS_PROXY_ := $(_HTTP_PROXY_)

export

.PHONY: all t test b build d debug c clean

all: build

t test:
	cd $(SELF)/ && cargo test -- --nocapture --test-threads=1

t-% test-%:
	cd $(SELF)/ && cargo test $* -- --nocapture

b build:
	cd $(SELF)/ && cargo build

d debug: build
	$(if $(NO_CACHE),rm -rf $(SELF)/target/debug/files/)
	cd $(SELF)/ && ./target/debug/$(PACKAGE_BIN)

c clean:
	rm -rf $(SELF)/target/

.PHONY: s static

s static: $(SELF)/Dockerfile $(wildcard $(SELF)/Cargo.*) $(wildcard $(SELF)/src/*.rs)
	docker build \
	--build-arg OPENSSL_VERSION=$(OPENSSL_VERSION) \
	--build-arg PACKAGE_LIB=$(PACKAGE_LIB) \
	--build-arg PACKAGE_BIN=$(PACKAGE_BIN) \
	-t $(PACKAGE_NAME)-builder -f $< $(SELF)/
	install -m u=rwx,go=rx -D /dev/null $(SELF)/target/static/$(PACKAGE_BIN)
	docker run --rm \
	-v $(SELF)/target/static/$(PACKAGE_BIN):/$(PACKAGE_BIN) \
	-t $(PACKAGE_NAME)-builder \
	/bin/sh -ec 'cat /usr/local/bin/$(PACKAGE_BIN) > /$(PACKAGE_BIN)'

.PHONY: dind dind-pull

dind:
	docker run --rm --privileged \
	--name $(PACKAGE_NAME)-dind \
	-v /etc/hosts:/etc/hosts \
	-v $(SELF)/target/debug/certs/ca.crt:/usr/local/share/ca-certificates/ca.crt \
	-e HTTP_PROXY=$(_HTTP_PROXY_) \
	-e HTTPS_PROXY=$(_HTTPS_PROXY_) \
	docker.io/library/docker:$(DOCKER_DIND_VERSION)

dind-pull:
	docker exec -t $(PACKAGE_NAME)-dind \
	/bin/sh -ec 'update-ca-certificates && docker rmi -f $(ARTIFACT1) && docker pull $(ARTIFACT1)'

.PHONY: pinp-pull

pinp-pull:
	podman run --rm --privileged \
	--name $(PACKAGE_NAME)-pinp \
	-v /etc/hosts:/etc/hosts \
	-v $(SELF)/target/debug/certs/ca.crt:/etc/pki/ca-trust/source/anchors/ca.crt \
	-e HTTP_PROXY=$(_HTTP_PROXY_) \
	-e HTTPS_PROXY=$(_HTTPS_PROXY_) \
	quay.io/podman/stable:$(PODMAN_PINP_VERSION) \
	/bin/sh -ec "update-ca-trust && podman pull --tls-verify=true $(ARTIFACT1)"

.PHONY: podman-pull

podman-pull:
	podman rmi -f $(ARTIFACT1) ||:
	HTTP_PROXY=$(_HTTP_PROXY_) \
	HTTPS_PROXY=$(_HTTPS_PROXY_) \
	podman --log-level=debug \
	pull --tls-verify=false \
	$(ARTIFACT1)

.PHONY: skopeo-pull

skopeo-pull:
	HTTP_PROXY=$(_HTTP_PROXY_) \
	HTTPS_PROXY=$(_HTTPS_PROXY_) \
	skopeo --debug --insecure-policy \
	copy --src-tls-verify=false \
	docker://$(ARTIFACT1) dir:$$(mktemp -d /tmp/dduct-skopeo-XXXX)
.PHONY: t-curl test-curl

t-curl test-curl:
	$(SHELL) $(SELF)/tests/curl.sh $(ARTIFACT2)
