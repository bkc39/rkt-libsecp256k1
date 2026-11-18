{
  description = "libsecp256k1 - Racket bindings to Bitcoin Core's libsecp256k1";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      version = "0.1";
      upstream = builtins.fromJSON (builtins.readFile ./native/upstream.json);
      so = pkgs: pkgs.stdenv.hostPlatform.extensions.sharedLibrary;
      libFile = pkgs: "libsecp256k1${so pkgs}";
      testEnv = pkgs: ''
        export LIBSECP256K1_TEST_SYSTEM_LIB=${pkgs.secp256k1}/lib/libsecp256k1${so pkgs}
        export LIBSECP256K1_CAST=${pkgs.foundry}/bin/cast
      '';
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };

          # The upstream release pinned in native/upstream.json, compiled by native/build.sh:
          # the compile line of the prebuilt libraries in native-libs/candidates/.
          native = pkgs.stdenv.mkDerivation {
            pname = "libsecp256k1-native";
            version = upstream.version;
            src = pkgs.fetchurl {
              name = "secp256k1-${upstream.version}.tar.gz";
              inherit (upstream) url sha256;
            };
            dontConfigure = true;
            buildPhase = ''
              runHook preBuild
              bash ${./native/build.sh} "$PWD" ${libFile pkgs}
              runHook postBuild
            '';
            installPhase = ''
              runHook preInstall
              install -Dm755 ${libFile pkgs} $out/lib/${libFile pkgs}
              install -Dm644 COPYING $out/share/licenses/libsecp256k1/COPYING
              runHook postInstall
            '';
          };

          # The Racket package with the native library injected into native-libs/.
          libsecp256k1 = pkgs.stdenv.mkDerivation {
            pname = "racket-libsecp256k1";
            inherit version;
            # cleanSource alone drops *.so, the committed linux candidate among them.
            src = pkgs.lib.cleanSourceWith {
              src = ./.;
              filter = path: type:
                pkgs.lib.cleanSourceFilter path type
                || pkgs.lib.hasInfix "/native-libs/candidates/" (toString path);
            };
            nativeBuildInputs = [ pkgs.racket ];
            buildInputs = [ native ];
            buildPhase = ''
              runHook preBuild
              export HOME=$TMPDIR/home
              export PLTUSERHOME=$TMPDIR/racket-home
              export LIBSECP256K1_NATIVE_LIB_PATH=${native}
              mkdir -p "$HOME" "$PLTUSERHOME" native-libs
              cp --no-preserve=mode ${native}/lib/${libFile pkgs} native-libs/
              raco pkg install --batch --deps fail --no-setup --copy --scope user \
                --name libsecp256k1 "$PWD"
              raco setup --check-pkg-deps --unused-pkg-deps --pkgs libsecp256k1
              runHook postBuild
            '';
            doCheck = true;
            checkPhase = ''
              runHook preCheck
              ${testEnv pkgs}
              export LIBSECP256K1_NATIVE_LIB_PATH=${native}
              racket -l racket/base -l libsecp256k1 \
                -e "(unless (eq? (libsecp256k1-origin) 'bundled) (exit 1))"
              raco test -x --timeout 120 -p libsecp256k1
              runHook postCheck
            '';
            installPhase = ''
              runHook preInstall
              mkdir -p $out/share
              cp -r $PLTUSERHOME $out/share/racket-home
              runHook postInstall
            '';
          };

          # Stages the Nix-built library into native-libs/ for work outside the dev shell.
          copy-native-libs = pkgs.writeShellApplication {
            name = "copy-native-libs";
            text = ''
              mkdir -p native-libs
              rm -f native-libs/${libFile pkgs}
              cp -v --no-preserve=mode ${native}/lib/${libFile pkgs} native-libs/
            '';
          };
        in
        {
          default = libsecp256k1;
          inherit native libsecp256k1 copy-native-libs;
        });

      apps = forAllSystems (system: {
        copy-native-libs = {
          type = "app";
          program = "${self.packages.${system}.copy-native-libs}/bin/copy-native-libs";
          meta.description = "Copy the Nix-built libsecp256k1 into native-libs/";
        };
      });

      checks = forAllSystems (system: {
        inherit (self.packages.${system}) native libsecp256k1;
      });

      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          native = self.packages.${system}.native;
        in
        {
          default = pkgs.mkShell {
            buildInputs = [ pkgs.racket pkgs.foundry pkgs.secp256k1 ];
            shellHook = ''
              ${testEnv pkgs}
              export LIBSECP256K1_NATIVE_LIB_PATH=${native}
              mkdir -p native-libs
              if ! cmp -s ${native}/lib/${libFile pkgs} native-libs/${libFile pkgs}; then
                rm -f native-libs/${libFile pkgs}
                cp --no-preserve=mode ${native}/lib/${libFile pkgs} native-libs/
              fi
              id=$(printf '%s' "$PWD" | sha256sum | cut -c1-12)
              export PLTUSERHOME="''${XDG_CACHE_HOME:-$HOME/.cache}/libsecp256k1-devshell/$id"
              stamp="$PLTUSERHOME/.setup-$(sha256sum info.rkt | cut -c1-12)"
              if [ ! -f "$stamp" ]; then
                mkdir -p "$PLTUSERHOME"
                raco pkg remove --batch --no-setup --scope user libsecp256k1 >/dev/null 2>&1
                raco pkg install --batch --link --deps fail --no-setup --scope user \
                  --name libsecp256k1 "$PWD" \
                  && raco setup --pkgs libsecp256k1 \
                  && rm -f "$PLTUSERHOME"/.setup-* && touch "$stamp"
              fi
            '';
          };
        });
    };
}
