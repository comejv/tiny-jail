{
  inputs = {
    nixpkgs.url = "nixpkgs";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
    }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };
      rust = pkgs.rust-bin.stable.latest.default.override {
        extensions = [
          "rust-src"
          "rustfmt"
          "clippy"
        ];
      };

      rustNightly = pkgs.rust-bin.selectLatestNightlyWith (
        toolchain:
        toolchain.default.override {
          extensions = [ "rust-src" ];
        }
      );
    in
    {
      devShells.${system} = {
        default = pkgs.mkShell {
          buildInputs = [
            rust
            pkgs.rust-analyzer-unwrapped
            pkgs.pkg-config
            pkgs.gcc
            pkgs.vimPlugins.nvim-treesitter-parsers.rust
            pkgs.cargo-tarpaulin

            pkgs.libseccomp

            pkgs.gdb
          ];
          shellHook = ''
            export CARGO_HOME=$PWD/.cargo
          '';
        };

        nightly = pkgs.mkShell {
          buildInputs = [
            rustNightly
            pkgs.cargo-fuzz
            pkgs.pkg-config
            pkgs.libseccomp
          ];
          shellHook = ''
            export CARGO_HOME=$PWD/.cargo
          '';
        };
      };
    };
}
