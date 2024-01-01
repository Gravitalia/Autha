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
          buildInputs = with pkgs;
            [ cargo rustc pkg-config openssl protobuf libiconv ]
            ++ (if lib.strings.hasInfix system "darwin" then [
              darwin.apple_sdk.frameworks.Security
              darwin.apple_sdk.frameworks.SystemConfiguration
              darwin.apple_sdk.frameworks.CoreServices
            ] else
              [ ]);
        };
      });
}

