#!/usr/bin/env bash
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <JAVA_HOME> <ARCH> <OPENSSL_VERSION>"
    echo "  JAVA_HOME: Path to Java installation"
    echo "  ARCH: Architecture to build for (x86_64 or arm64)"
    echo "  OPENSSL_VERSION: OpenSSL version to link against (1.1 or 3)"
    exit 1
fi;

JAVA_HOME=$1
ARCH=$2
OPENSSL_VERSION=$3

case $ARCH in
    "x86-64"|"x86_64")
        INSTALL_PREFIX_ARCH=x86-64
        OSX_ARCH=x86_64
        ;;
    "arm64"|"aarch64")
        INSTALL_PREFIX_ARCH=aarch64
        OSX_ARCH=arm64
        ;;
esac

cmake -B cmake-build \
    -DJITSI_SRTP_LIBSSL_VERSION="$OPENSSL_VERSION" \
    -DJAVA_HOME="$JAVA_HOME" \
    -DCMAKE_INSTALL_PREFIX="src/main/resources/darwin-$INSTALL_PREFIX_ARCH" \
    -DCMAKE_OSX_ARCHITECTURES="$OSX_ARCH" \
    -DOPENSSL_ROOT_DIR="/usr/local/opt/openssl@$OPENSSL_VERSION"
cmake --build cmake-build --config Release --target install
