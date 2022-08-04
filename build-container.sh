#!/bin/bash

UPLOAD=0

if [ "$1" = "--upload" ]; then
	UPLOAD=1
fi


VERSION=$(cat VERSION)
VER=( ${VERSION//./ } )

sudo podman pull registry.opensuse.org/opensuse/busybox:latest
sudo podman build --build-arg VERSION="${VERSION}" --build-arg BUILDTIME=$(date +%Y-%m-%dT%TZ) -t mws .
sudo podman tag localhost/thkukuk/mws thkukuk/mws:"${VERSION}"
sudo podman tag localhost/thkukuk/mws thkukuk/mws:latest
sudo podman tag localhost/thkukuk/mws thkukuk/mws:"${VER[0]}"
sudo podman tag localhost/thkukuk/mws thkukuk/mws:"${VER[0]}.${VER[1]}"
if [ $UPLOAD -eq 1 ]; then
	sudo podman login docker.io
	sudo podman push thkukuk/mws:"${VERSION}"
	sudo podman push thkukuk/mws:latest
	sudo podman push thkukuk/mws:"${VER[0]}"
	sudo podman push thkukuk/mws:"${VER[0]}.${VER[1]}"
fi
