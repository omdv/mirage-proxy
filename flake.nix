{
  description = "Rust development template";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  };

  outputs = { nixpkgs, ... }: let
    systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
    forEachSystem = nixpkgs.lib.genAttrs systems;
  in {
    devShells = forEachSystem (system: let
      pkgs = import nixpkgs { inherit system; };
    in {
      default = pkgs.mkShell {
        packages = with pkgs; [
          cargo
          rustc
          rust-analyzer
          rustfmt
          clippy
        ];

        # Set RUST_SRC_PATH so rust-analyzer can find standard library source
        RUST_SRC_PATH = pkgs.rustPlatform.rustLibSrc;

        shellHook = ''
          echo "Rust $(rustc --version) | Cargo $(cargo --version)"
        '';
      };
    });
  };
}
