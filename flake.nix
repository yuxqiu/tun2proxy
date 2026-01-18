{
  description = "tun2proxy Rust project as a multi-system flake with dev shell";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        tun2proxy = pkgs.rustPlatform.buildRustPackage {
          pname = "tun2proxy";
          version = self.shortRev or self.dirtyShortRev or "unknown";
          src = self;
          cargoLock.lockFile = ./Cargo.lock;
          env = {
            GIT_HASH = self.shortRev or self.dirtyShortRev or "unknown";
          };
        };
      in
      {
        # Buildable Rust package
        packages = {
          tun2proxy = tun2proxy;
          default = tun2proxy;
        };
        # Make it runnable with nix run
        apps.tun2proxy = {
          type = "app";
          program = "${tun2proxy}/bin/tun2proxy";
        };
        apps.default = self.apps.${system}.tun2proxy;
        # Development shell
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.rustc
            pkgs.cargo
            self.packages.${system}.tun2proxy
          ];
        };
      }
    );
}
