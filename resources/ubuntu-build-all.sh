#!/usr/bin/env bash
PROJECT_DIR="$(realpath "$(dirname "$0")/../")"
JAVA_VERSION=11
ARCHS=(amd64 arm64 ppc64el)
declare -A VERSIONS=([focal]="1.1" [jammy]="3")

for ARCH in "${ARCHS[@]}"; do
    for DIST in "${!VERSIONS[@]}"; do
        "$PROJECT_DIR/resources/ubuntu-build-docker.sh" "$ARCH" "$DIST" "$JAVA_VERSION" "${VERSIONS[$DIST]}"
    done;
done;
