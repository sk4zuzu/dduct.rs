SHELL := $(shell which bash)
SELF  := $(patsubst %/,%,$(dir $(abspath $(firstword $(MAKEFILE_LIST)))))

PACKAGE_NAME := dduct
PACKAGE_LIB  := lib$(PACKAGE_NAME)
PACKAGE_BIN  := $(PACKAGE_NAME)

RUST_LOG       := debug
RUST_BACKTRACE := full

OPENSSL_VERSION := 1_1_1m

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
