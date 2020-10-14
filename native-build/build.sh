#!/bin/bash

set -e

secp256k1_rev=63150ab4da1ef13ebfb4396064e1ff501dbd015e

script_path="$(dirname "$0")"
cd "$script_path"

build_platform () {
  echo "Building $1"
  rm -rf dist/$1
  DOCKER_BUILDKIT=1 docker build \
    --progress=plain --build-arg secp256k1_rev=$secp256k1_rev \
    -o native/$1 -f ./dockerfiles/$1.Dockerfile .
}

case $DIST_TARGET_FILTER in
  (*[![:blank:]]*)
    case $DIST_TARGET_FILTER in
      linux-x64)      build_platform linux-x64 ;;
      linux-musl-x64) build_platform linux-musl-x64 ;;
      linux-arm7)     build_platform linux-arm7 ;;
      linux-arm64)    build_platform linux-arm64 ;;
      win-x64)        build_platform win-x64 ;;
      win-x86)        build_platform win-x86 ;;
      macos-x64)      build_platform macos-x64 ;;
      *)
        echo "Invalid dist target filter '$DIST_TARGET_FILTER'"
        exit 1
        ;;
    esac
    ;;
  (*)
    echo "Building distrubtions for all targets."
    build_platform linux-x64
    build_platform linux-musl-x64
    build_platform linux-arm7
    build_platform linux-arm64
    build_platform win-x64
    build_platform win-x86
    build_platform macos-x64
    ;;
esac