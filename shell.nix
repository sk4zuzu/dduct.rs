{ pkgs ? import <nixpkgs> {} }:

with pkgs;

stdenv.mkDerivation {
  name = "dduct-env";
  buildInputs = [
    clang
    pkgconfig
    openssl
  ];
}
