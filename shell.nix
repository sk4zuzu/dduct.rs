{ pkgs ? import <nixpkgs> {} }:

with pkgs;

stdenv.mkDerivation {
  name = "dduct-env";
  buildInputs = [
    clang
    openssl
    pkgconfig
    skopeo
  ];
}
