{ pkgs ? import <nixpkgs> {} }:

with pkgs;

stdenv.mkDerivation {
  name = "dduct-env";
  nativeBuildInputs = [
    clang
    openssl
    pkg-config
    skopeo
  ];
}
