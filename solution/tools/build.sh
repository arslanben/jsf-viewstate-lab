#!/usr/bin/env bash
# Regenerates the payload TEMPLATE used by solution/solve.py.
# Must run under JDK 8 (the target's runtime), e.g.:
#
#   docker run --rm -v "$PWD":/tools -w /tools tomcat:9-jdk8-temurin bash build.sh
#
set -eux

M2=https://repo1.maven.org/maven2
TOOLS=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cp "$TOOLS"/Translet.java "$TOOLS"/BuildPayload.java "$WORK"/
cd "$WORK"

curl -fsSL -o "$WORK"/beanutils.jar \
    "$M2"/commons-beanutils/commons-beanutils/1.9.2/commons-beanutils-1.9.2.jar
curl -fsSL -o "$WORK"/collections.jar \
    "$M2"/commons-collections/commons-collections/3.1/commons-collections-3.1.jar
curl -fsSL -o "$WORK"/logging.jar \
    "$M2"/commons-logging/commons-logging/1.2/commons-logging-1.2.jar

# proprietary-API warnings are expected on JDK 8
javac -encoding UTF-8 Translet.java
javac -encoding UTF-8 -cp beanutils.jar:collections.jar:logging.jar BuildPayload.java

java -cp .:beanutils.jar:collections.jar:logging.jar BuildPayload Translet.class
