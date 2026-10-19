#!/bin/bash

set -e

VERSION=$(grep -oP "^\s*version\s*:\s*'\K[^']+" meson.build)
VER=( ${VERSION//./ } )

sudo podman pull registry.opensuse.org/opensuse/busybox:latest
sudo podman build --rm --no-cache --build-arg VERSION="${VERSION}" --build-arg BUILDTIME=$(date +%Y-%m-%dT%TZ) -t mws .
sudo podman tag localhost/mws thkukuk/mws:"${VERSION}"
sudo podman tag localhost/mws thkukuk/mws:latest
sudo podman tag localhost/mws thkukuk/mws:"${VER[0]}"
sudo podman tag localhost/mws thkukuk/mws:"${VER[0]}.${VER[1]}"
