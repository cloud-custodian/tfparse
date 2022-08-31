#!/usr/bin/env sh

ARCH=$(uname -m)
case $ARCH in
    x86_64) ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
esac
curl "https://storage.googleapis.com/golang/go1.18.linux-${ARCH}.tar.gz" --silent --location | tar -xz

export PATH="$(pwd)/go/bin:$PATH"