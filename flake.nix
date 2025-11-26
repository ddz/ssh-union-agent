{
  description = "SSH union agent - forwards requests to multiple upstream SSH agents";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.buildGoModule {
          pname = "ssh-union-agent";
          version = "0.1.0";
          src = ./.;
          vendorHash = "sha256-0Upxa7S3OuhdzeY6VZy2eZ6Rs45WTNw4U93KRlkQkWg=";
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go
          ];
        };
      }
    );
}
