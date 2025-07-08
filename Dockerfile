ARG RELEASE=jammy
FROM mcr.microsoft.com/devcontainers/base:${RELEASE}

RUN apt-get update
COPY build.sh /tmp
RUN /tmp/build.sh -i
RUN  pip3 install pylint