#!/usr/bin/env bash
if ! command -v unzip &> /dev/null; then
    echo "$0 requires unzip"
fi;

VER=3.3.0
PROJECT_DIR="$(cd "$(dirname "$0")"; pwd -P)/../"
EXTRACT_DEST="$PROJECT_DIR/target/latest-maven"

mkdir -p "$EXTRACT_DEST"
mvn org.apache.maven.plugins:maven-dependency-plugin:$VER:copy \
    -Dartifact=org.jitsi:jitsi-srtp:LATEST:jar \
    -DoutputDirectory="$EXTRACT_DEST"

unzip -o "$EXTRACT_DEST/*.jar" "linux-*" "darwin-*" -d "$EXTRACT_DEST"
mkdir -p "$PROJECT_DIR/src/main/resources"
cp -r "$EXTRACT_DEST/"{darwin,linux}-* "$PROJECT_DIR/src/main/resources" || true
