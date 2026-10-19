#!/bin/bash

set -e

VERSION=$(grep -oP "^\s*version\s*:\s*'\K[^']+" meson.build)
VER=( ${VERSION//./ } )

run0 podman pull registry.opensuse.org/opensuse/busybox:latest
run0 podman build --rm --no-cache --build-arg VERSION="${VERSION}" --build-arg BUILDTIME=$(date +%Y-%m-%dT%TZ) -t mws .
run0 podman tag localhost/mws thkukuk/mws:"${VERSION}"
run0 podman tag localhost/mws thkukuk/mws:latest
run0 podman tag localhost/mws thkukuk/mws:"${VER[0]}"
run0 podman tag localhost/mws thkukuk/mws:"${VER[0]}.${VER[1]}"
