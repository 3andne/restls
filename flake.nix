rec {
  description = "Restls Protocol: A Perfect Impersonation of TLS; Restls协议: 对TLS的完美伪装";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/master";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (system: {
      packages = let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [self.overlays.restls];
        };
      in rec {
        restls = pkgs.restls;
        default = restls;
      };

      apps = rec {
        restls = flake-utils.lib.mkApp {drv = self.packages.${system}.restls;};
        default = restls;
      };
    })
    // {
      overlays = rec {
        restls = final: prev: let
          name = "restls";
          pname = name;
          version = final.lib.substring 0 8 self.lastModifiedDate or self.lastModified or "19700101";
          homepage = "https://github.com/3andne/restls";
        in {
          restls = final.rustPlatform.buildRustPackage {
            inherit pname version;

            src = ./.;

            cargoLock = {
              lockFile = ./Cargo.lock;
            };

            meta = with final.lib; {
              inherit description homepage;
              license = licenses.bsd3;
            };
          };
        };

        default = restls;
      };
    };
}
