[![dnsjava CI](https://github.com/jitsi/jitsi-srtp/actions/workflows/maven.yml/badge.svg)](https://github.com/jitsi/jitsi-srtp/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/jitsi/jitsi-srtp/branch/master/graph/badge.svg?token=2CTBVOFNVJ)](https://codecov.io/gh/jitsi/jitsi-srtp)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.jitsi/jitsi-srtp/badge.svg)](https://search.maven.org/artifact/org.jitsi/jitsi-srtp)
[![javadoc](https://javadoc.io/badge2/org.jitsi/jitsi-srtp/javadoc.svg)](https://javadoc.io/doc/jitsi/jitsi-srtp)

# Jitsi SRTP

Jitsi SRTP contains classes for encrypting and decrypting SRTP and SRTCP
packets.

## Building with Java changes only

To avoid having to build all native libraries,
execute `resources/fetch-maven.sh` to download and extract the native binaries
from the latest release on Maven Central.

## Building the native libraries

Jitsi SRTP contains native libraries to speed up encryption/decryption. The
artifacts released
to [Maven Central]((https://search.maven.org/artifact/org.jitsi/jitsi-srtp))
contain pre-built binaries for Ubuntu for OpenSSL 1.1 and 3.

**Please take a look at the GitHub Actions build before asking for more detailed
build instructions!**

### Ubuntu

Prerequisites:

- OpenJDK 11 (or newer)
- Maven
- Docker

Run `mvn compile` to generate the JNI headers, then
run `resources/ubuntu-build-all.sh`.
The script creates Docker images for each architecture and OpenSSL version.

### Mac

Prerequisites:

- OpenJDK 11 (or newer) for the intended architectures
- XCode
- CMake
- Maven
- OpenSSL (intended version and architecture)

Run `mvn compile` to generate the JNI headers, then run `resources/mac-cmake.sh`
.
