SHELL := $(shell which bash)
SELF  := $(patsubst %/,%,$(dir $(abspath $(firstword $(MAKEFILE_LIST)))))

PACKAGE_NAME := dduct
PACKAGE_LIB  := lib$(PACKAGE_NAME)
PACKAGE_BIN  := $(PACKAGE_NAME)

RUST_LOG       := debug
RUST_BACKTRACE := full

OPENSSL_VERSION := 1_1_1m

define DOCKERFILE
FROM docker.io/library/ubuntu:22.04

RUN apt-get -q update \
 && DEBIAN_FRONTEND=noninteractive apt-get -q install -y \
    bash \
    curl \
    make \
    musl-dev \
    musl-tools \
    perl

RUN ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/x86_64-linux-musl/asm \
 && ln -s /usr/include/asm-generic /usr/include/x86_64-linux-musl/asm-generic \
 && ln -s /usr/include/linux /usr/include/x86_64-linux-musl/linux

WORKDIR /build/openssl/

RUN curl -fsSL https://github.com/openssl/openssl/archive/OpenSSL_$(OPENSSL_VERSION).tar.gz \
  | tar -xz -f- --strip-components=1 -C ./ \
 && CC="musl-gcc -fPIE -pie" ./Configure no-shared no-async --prefix=/musl --openssldir=/musl/ssl linux-x86_64 \
 && make depend \
 && make -j4 \
 && make install_sw install_ssldirs \
 && rm -rf /build/openssl/

ENV OPENSSL_STATIC=true
ENV OPENSSL_DIR=/musl

ENV PATH=/root/.cargo/bin:$$PATH

RUN curl --proto "=https" --tlsv1.2 -Sf https://sh.rustup.rs \
    | bash -s -- -y --default-toolchain stable-x86_64-unknown-linux-gnu \
 && rustup target add x86_64-unknown-linux-musl

WORKDIR /build/

COPY Cargo.toml Cargo.lock ./
RUN install -d ./src/ \
 && echo "" >./src/lib.rs \
 && echo "fn main() {}" >./src/bin.rs \
 && cargo build \
    --target x86_64-unknown-linux-musl \
    --release \
 && find ./target/x86_64-unknown-linux-musl/ -name '$(PACKAGE_LIB)*' -o -name '$(PACKAGE_BIN)*' \
    | xargs rm -rf

COPY /src/ ./src/
RUN cargo build \
    --target x86_64-unknown-linux-musl \
    --release \
 && strip --strip-unneeded ./target/x86_64-unknown-linux-musl/release/$(PACKAGE_BIN)

VOLUME /target/

ENTRYPOINT []
CMD cat ./target/x86_64-unknown-linux-musl/release/$(PACKAGE_BIN) > /$(PACKAGE_BIN)
endef

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

s static: $(wildcard $(SELF)/Cargo.*) $(wildcard $(SELF)/src/*.rs)
	docker build -t $(PACKAGE_NAME)-builder -f- $(SELF)/ <<< "$$DOCKERFILE"
	install -m u=rwx,go=rx -D /dev/null $(SELF)/target/static/$(PACKAGE_BIN)
	docker run -v $(SELF)/target/static/$(PACKAGE_BIN):/$(PACKAGE_BIN) --rm -t $(PACKAGE_NAME)-builder
