FROM docker.io/library/ubuntu:22.04 AS BUILD

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

ARG OPENSSL_VERSION

RUN curl -fsSL https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz \
  | tar -xz -f- --strip-components=1 -C ./ \
 && CC="musl-gcc -fPIE -pie" ./Configure no-shared no-async --prefix=/musl --openssldir=/musl/ssl linux-x86_64 \
 && make depend \
 && make -j4 \
 && make install_sw install_ssldirs \
 && rm -rf /build/openssl/

ENV OPENSSL_STATIC=true
ENV OPENSSL_DIR=/musl

ENV PATH=/root/.cargo/bin:$PATH

RUN curl --proto "=https" --tlsv1.2 -Sf https://sh.rustup.rs \
    | bash -s -- -y --default-toolchain stable-x86_64-unknown-linux-gnu \
 && rustup target add x86_64-unknown-linux-musl

WORKDIR /build/

COPY Cargo.toml Cargo.lock ./

ARG PACKAGE_LIB
ARG PACKAGE_BIN

RUN install -d ./src/ \
 && echo "" >./src/lib.rs \
 && echo "fn main() {}" >./src/bin.rs \
 && cargo build \
    --target x86_64-unknown-linux-musl \
    --release \
 && find ./target/x86_64-unknown-linux-musl/ -name "$PACKAGE_LIB*" -o -name "$PACKAGE_BIN*" \
    | xargs rm -rf

COPY /src/ ./src/
RUN cargo build \
    --target x86_64-unknown-linux-musl \
    --release \
 && strip --strip-unneeded ./target/x86_64-unknown-linux-musl/release/$PACKAGE_BIN

FROM docker.io/library/alpine:3.19 AS SERVE

ARG PACKAGE_BIN

COPY --from=BUILD /build/target/x86_64-unknown-linux-musl/release/$PACKAGE_BIN /usr/local/bin/

ENTRYPOINT []
CMD /usr/local/bin/dduct
