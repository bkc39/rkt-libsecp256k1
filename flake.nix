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
      # Test-only: the system-library route and the cast differential.
      testEnv = pkgs: ''
        export LIBSECP256K1_TEST_SYSTEM_LIB=${pkgs.secp256k1}/lib/libsecp256k1${pkgs.stdenv.hostPlatform.extensions.sharedLibrary}
        export LIBSECP256K1_CAST=${pkgs.foundry}/bin/cast
      '';
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          libsecp256k1 = pkgs.stdenv.mkDerivation {
            pname = "racket-libsecp256k1";
            inherit version;
            src = pkgs.lib.cleanSource ./.;
            nativeBuildInputs = [ pkgs.racket ];
            buildPhase = ''
              runHook preBuild
              export HOME=$TMPDIR/home
              export PLTUSERHOME=$TMPDIR/racket-home
              mkdir -p "$HOME" "$PLTUSERHOME"
              raco pkg install --batch --deps fail --no-setup --copy --scope user \
                --name libsecp256k1 "$PWD"
              # The pre-installer compiles native/secp256k1 with stdenv's cc.
              raco setup --check-pkg-deps --unused-pkg-deps --pkgs libsecp256k1
              runHook postBuild
            '';
            doCheck = true;
            checkPhase = ''
              runHook preCheck
              ${testEnv pkgs}
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
        in
        {
          default = libsecp256k1;
          inherit libsecp256k1;
        });

      checks = forAllSystems (system: {
        inherit (self.packages.${system}) libsecp256k1;
      });

      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          default = pkgs.mkShell {
            buildInputs = [ pkgs.racket pkgs.foundry pkgs.secp256k1 ];
            shellHook = ''
              ${testEnv pkgs}
              # Outside $PWD: raco pkg install --link rejects overlapping collects dirs.
              cache_root="''${XDG_CACHE_HOME:-$HOME/.cache}/libsecp256k1-devshell"
              project_id=$(printf '%s' "$PWD" | ${pkgs.coreutils}/bin/sha256sum | cut -c1-12)
              export PLTUSERHOME="$cache_root/$project_id"
              mkdir -p "$PLTUSERHOME"
              stamp="$PLTUSERHOME/.setup-$(${pkgs.coreutils}/bin/sha256sum info.rkt | cut -c1-12)"
              if [ ! -f "$stamp" ]; then
                echo "Setting up libsecp256k1 in $PLTUSERHOME (info.rkt changed or first run)"
                rm -f "$PLTUSERHOME"/.setup-* 2>/dev/null || true
                raco pkg remove --batch --no-setup --scope user libsecp256k1 >/dev/null 2>&1 || true
                if raco pkg install --batch --link --deps fail --no-setup --scope user \
                     --name libsecp256k1 "$PWD" \
                   && raco setup --check-pkg-deps --unused-pkg-deps --pkgs libsecp256k1; then
                  touch "$stamp"
                  echo "Done. Try: raco test -x -p libsecp256k1"
                else
                  echo "libsecp256k1 setup FAILED; stamp not written, will retry next shell entry." >&2
                fi
              fi
            '';
          };
        });
    };
}
