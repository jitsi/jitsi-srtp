ARG DIST=focal

FROM ubuntu:$DIST

ARG DIST
ARG ARCH=amd64
ARG JAVA_VERSION=11

ADD https://github.com/Kitware/CMake/releases/download/v3.23.1/cmake-3.23.1-Linux-x86_64.sh /opt/cmake.sh
RUN chmod 755 /opt/cmake.sh && /opt/cmake.sh --skip-license --prefix=/usr --exclude-subdir && rm -f /opt/cmake.sh

COPY sources_${DIST}_${ARCH}.list /etc/apt/sources.list

COPY --chmod=755 ubuntu-packages.sh /opt/
RUN /opt/ubuntu-packages.sh $ARCH $JAVA_VERSION
