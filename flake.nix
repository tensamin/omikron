{
  description = "Omikron packages and development shell";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    type-maps = {
      url = "github:tensamin/mtp-type-maps";
      flake = false;
    };
    tau-src = {
      url = "github:TensaminDev/Tau/d6183368f3e2b91b3c3d86eae3802654b349be10";
      flake = false;
    };
    mtp-src = {
      url = "github:Nonanium/MTP/eef7562be64e77d8c29ba5af6df7596073e3c9f2";
      flake = false;
    };
    iota-src = {
      url = "github:TensaminDev/Iota/060387affdef2c683aa1e87f31fbfc1e3ff7ccf4";
      flake = false;
    };
  };
  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      type-maps,
      tau-src,
      mtp-src,
      iota-src,
      ...
    }:
    let
      systems = nixpkgs.lib.genAttrs [
        "x86_64-linux"
        "aarch64-linux"
      ];
      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
      rustFor =
        pkgs:
        pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rustfmt"
            "clippy"
          ];
        };
    in
    {
      lib.mkPackage =
        {
          rustPlatform,
          pkgs,
          source,
          cargoDeps,
          typeMaps,
        }:
        rustPlatform.buildRustPackage {
          pname = "omikron";
          version = "0.1.0";
          src = source;
          inherit cargoDeps;
          nativeBuildInputs = [
            pkgs.cmake
            pkgs.perl
            pkgs.pkg-config
          ];
          buildInputs = [
            pkgs.openssl
            pkgs.sqlite
          ];
          dontUseCmakeConfigure = true;
          MTP_TYPE_MAPS = "${typeMaps}/type-maps.yaml";
          doCheck = false;
          meta = {
            platforms = [
              "x86_64-linux"
              "aarch64-linux"
            ];
            mainProgram = "omikron";
          };
        };
      lib.mkContainer =
        {
          pkgs,
          package,
          revision,
        }:
        pkgs.dockerTools.buildLayeredImage {
          name = "tensamin/omikron";
          tag = revision;
          contents = [
            package
            pkgs.cacert
            pkgs.dockerTools.binSh
          ];
          config = {
            Entrypoint = [ "${package}/bin/omikron" ];
            WorkingDir = "/var/lib/omikron";
            Env = [ "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt" ];
          };
        };
      packages = systems (
        system:
        let
          pkgs = pkgsFor system;
          rust = rustFor pkgs;
          rustPlatform = pkgs.makeRustPlatform {
            cargo = rust;
            rustc = rust;
          };
          source = pkgs.runCommand "omikron-source" { } ''
            cp -r ${self} "$out"
            chmod -R u+w "$out"
            rm -rf "$out/mtp-type-maps"
            cp -r ${type-maps} "$out/mtp-type-maps"
          '';
        in
        {
          default = self.lib.mkPackage {
            inherit pkgs rustPlatform source;
            typeMaps = type-maps;
            cargoDeps = rustPlatform.fetchCargoVendor {
              pname = "omikron";
              version = "0.1.0";
              src = source;
              hash = "sha256-dcru0vNhKANoyvKpmioGdX1VHP5dWZuoRK0B9X952HY=";
            };
          };
          container = self.lib.mkContainer {
            inherit pkgs;
            package = self.packages.${system}.default;
            revision = self.shortRev or "local";
          };
        }
      );
      checks = systems (system: {
        inherit (self.packages.${system}) default;
      });
      devShells = systems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            packages = [
              (rustFor pkgs)
              pkgs.git
              pkgs.cmake
              pkgs.perl
              pkgs.pkg-config
            ];
            buildInputs = [
              pkgs.openssl
              pkgs.sqlite
            ];
            MTP_TYPE_MAPS = "${type-maps}/type-maps.yaml";
          };
        }
      );
    };
}
