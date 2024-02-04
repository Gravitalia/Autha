{
  description =
    "Set up a devShell for a Rust project with necessary dependencies.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = nixpkgs.legacyPackages.${system};
      in {
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [pkg-config] ++
          lib.optionals stdenv.buildPlatform.isDarwin [
            pkgs.darwin.apple_sdk.frameworks.CoreFoundation
            pkgs.darwin.apple_sdk.frameworks.CoreServices
            pkgs.darwin.apple_sdk.frameworks.Security 
            pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
          ];

          buildInputs = with pkgs;
            [ rustc cargo rustfmt gcc clippy openssl protobuf libiconv bazel_6 bazel-buildtools ];
        };
      }
    );
}
