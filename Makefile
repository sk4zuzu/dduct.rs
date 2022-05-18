# vim:ts=4:sw=4:noet:

SHELL := $(shell which bash)
SELF  := $(patsubst %/,%,$(dir $(abspath $(firstword $(MAKEFILE_LIST)))))

PACKAGE_NAME := dduct
PACKAGE_LIB  := lib$(PACKAGE_NAME)
PACKAGE_BIN  := $(PACKAGE_NAME)

RUST_LOG       := debug
RUST_BACKTRACE := full

OPENSSL_VERSION := 1_1_1m

NO_CACHE ?=

_HTTP_PROXY_  := http://10.2.11.1:8000
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

.PHONY: dind dind-exec dind-pull

dind:
	docker run --rm --privileged \
	--name $(PACKAGE_NAME)-dind \
	-v $(SELF)/target/debug/certs/ca.crt:/usr/local/share/ca-certificates/ca.crt \
	-v $(SELF)/target/debug/certs/server.crt:/usr/local/share/ca-certificates/server.crt \
	-e HTTP_PROXY=$(_HTTP_PROXY_) \
	-e HTTPS_PROXY=$(_HTTPS_PROXY_) \
	docker.io/library/docker:20.10.16-dind-alpine3.15

dind-exec:
	docker exec -it $(PACKAGE_NAME)-dind /bin/sh

dind-pull:
	docker exec -t $(PACKAGE_NAME)-dind \
	/bin/sh -ec '(update-ca-certificates ||:); (docker rmi alpine:latest ||:); docker pull alpine:latest'
