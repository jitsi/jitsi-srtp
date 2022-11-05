#!/usr/bin/env bash
if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <ARCH> <JAVA_VERSION> <DIR> <OPENSSL_VERSION>"
    echo "  ARCH: Architecture to build for (amd64, arm64, ppc64el)"
    echo "  JAVA_VERSION: Java version (11)"
    echo "  DIR: jitsi-srtp project directory"
    echo "  OPENSSL_VERSION: OpenSSL version to link against (1.1 or 3)"
    exit 1
fi;

ARCH=$1
JAVA_VERSION=$2
DIR=$3
OPENSSL_VERSION=$4

cd $DIR || exit 1
echo $ARCH
echo $JAVA_VERSION
if [ -f "cmake/$ARCH-linux-gnu.cmake" ]; then
    TOOLCHAIN_FILE="cmake/$ARCH-linux-gnu.cmake"
fi;

export JAVA_HOME=/usr/lib/jvm/java-$JAVA_VERSION-openjdk-$ARCH/
echo $JAVA_HOME
java -version

rm -rf cmake-build
cmake -B cmake-build \
    -DJITSI_SRTP_LIBSSL_VERSION=$OPENSSL_VERSION \
    -DJAVA_HOME:PATH=$JAVA_HOME \
    -DCMAKE_TOOLCHAIN_FILE:PATH="$TOOLCHAIN_FILE"
cmake --build cmake-build --config Release --target install
