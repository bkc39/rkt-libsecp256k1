# Every parameter of a candidate build that native/upstream.json and native/build.sh do not
# hold: the linux build image, the compilers, the macOS deployment target and how the darwin
# library is finished.  scripts/build-so.sh sources it.  It is a build input of every
# candidate (native-libs/BUILDING.md): changing it means rebuilding all of them.

MANYLINUX_IMAGE="quay.io/pypa/manylinux2014_x86_64"
MANYLINUX_DIGEST="sha256:f6077fab327d7823d7cee287b93ef63efe3af0e234add7503121247c1475ebec"
LINUX_CC=gcc

DARWIN_CC=cc
DARWIN_DEPLOYMENT_TARGET=11.0

darwin_finish() {
  install_name_tool -id "@rpath/$(basename "$1")" "$1"
  codesign -f -s - "$1"
}
