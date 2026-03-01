# other/docker/codeql/codeql.Dockerfile
FROM toxchat/c-toxcore:sources AS sources
FROM ubuntu:22.04

RUN apt-get update && \
    DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    curl \
    git \
    libconfig-dev \
    libopus-dev \
    libsodium-dev \
    libvpx-dev \
    ninja-build \
    pkg-config \
    unzip \
    wget \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install CodeQL
ARG CODEQL_VERSION=v2.23.9
RUN curl -L -o /tmp/codeql.zip https://github.com/github/codeql-cli-binaries/releases/download/${CODEQL_VERSION}/codeql-linux64.zip && \
    unzip -q /tmp/codeql.zip -d /opt && \
    rm /tmp/codeql.zip

ENV PATH="/opt/codeql:$PATH"

RUN groupadd -r -g 1000 builder \
 && useradd -m --no-log-init -r -g builder -u 1000 builder

WORKDIR /home/builder/c-toxcore

# Copy sources
COPY --chown=builder:builder --from=sources /src/ /home/builder/c-toxcore/

# Pre-create build directory
RUN mkdir -p build codeql-db && chown builder:builder codeql-db build

# Copy scripts
COPY --chown=builder:builder other/docker/codeql/build.sh .
COPY --chown=builder:builder other/docker/codeql/run-analysis.sh .

RUN chmod +x build.sh run-analysis.sh

USER builder

# Download standard queries as builder
RUN codeql pack download codeql/cpp-queries

CMD ["./run-analysis.sh"]
