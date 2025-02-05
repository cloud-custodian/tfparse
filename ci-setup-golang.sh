#!/usr/bin/env sh

OS=$(uname -s)
ARCH=$(uname -m)
GOVER="1.23.5"
case $ARCH in
    x86_64) ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
esac
case $OS in
    Darwin) OS="darwin" ;;
    Linux) OS="linux" ;;
esac    
	    
curl "https://storage.googleapis.com/golang/go${GOVER}.${OS}-${ARCH}.tar.gz" --silent --location | tar -xz

export PATH="$(pwd)/go/bin:$PATH"





