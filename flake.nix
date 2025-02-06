{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane = {
      url = "github:ipetkov/crane";
    };
  };
  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          overlays = [
            (import rust-overlay)
            (import ./rocksdb-overlay.nix)
            (import ./elementsd-overlay.nix)

          ];
          pkgs = import nixpkgs {
            inherit system overlays;
          };
          inherit (pkgs) lib;
          rustToolchain = pkgs.pkgsBuildHost.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

          src = lib.cleanSourceWith {
            src = ./.; # The original, unfiltered source
            filter = path: type:
              # (lib.hasSuffix "\.css" path) ||
              (lib.hasInfix "/tests/data/" path) ||
              (craneLib.filterCargoSources path type)
            ;
          };

          nativeBuildInputs = with pkgs; [ rustToolchain pkg-config clang ];
          buildInputs = with pkgs; [ openssl ];
          commonArgs = {
            inherit src buildInputs nativeBuildInputs;

            LIBCLANG_PATH = "${pkgs.libclang.lib}/lib"; # for rocksdb

            # link rocksdb dynamically
            ROCKSDB_INCLUDE_DIR = "${pkgs.rocksdb}/include";
            ROCKSDB_LIB_DIR = "${pkgs.rocksdb}/lib";

            ELEMENTSD_EXEC = "${pkgs.elementsd}/bin/elementsd";


          };
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;
          bin = craneLib.buildPackage (commonArgs // {
            inherit cargoArtifacts;
          });
        in
        with pkgs;
        {
          packages =
            {
              inherit bin;
              default = bin;
            };
          devShells.default = mkShell {
            inputsFrom = [ bin ];

            LIBCLANG_PATH = "${pkgs.libclang.lib}/lib"; # for building rocksdb

            # to link rocksdb dynamically
            ROCKSDB_INCLUDE_DIR = "${pkgs.rocksdb}/include";
            ROCKSDB_LIB_DIR = "${pkgs.rocksdb}/lib";

            ELEMENTSD_EXEC = "${pkgs.elementsd}/bin/elementsd";

            buildInputs = with pkgs; [ ];
          };
        }
      );
}
