# This Docker build emulates roughly what Travis CI is doing. It is not exactly
# the same (different tool versions) and success in this image may not
# necessarily mean success on Travis. This image is also not automatically
# tested, so it may get out of date. Send PRs if you use it and it's broken.
#
# For one, we use bionic, not xenial, because xenial's clang is way too old.
FROM ubuntu:16.04

# Travis environment.
RUN apt-get update && apt-get install --no-install-recommends -y \
 apt-transport-https \
 build-essential \
 ca-certificates \
 curl \
 git \
 pkg-config \
 python-pip \
 python-setuptools \
 python3 \
 software-properties-common \
 wget \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN curl https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - \
 && apt-add-repository "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-6.0 main" \
 && apt-get update && apt-get install --no-install-recommends -y \
 clang-6.0 \
 clang-format-6.0 \
 llvm-6.0 \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN ls /usr/bin/clang-6.0 && ln -s /usr/bin/clang-6.0 /usr/bin/clang \
 && ls /usr/bin/clang++-6.0 && ln -s /usr/bin/clang++-6.0 /usr/bin/clang++ \
 && ls /usr/bin/clang-format-6.0 && ln -s /usr/bin/clang-format-6.0 /usr/bin/clang-format \
 && ls /usr/bin/opt-6.0 && ln -s /usr/bin/opt-6.0 /usr/bin/opt

# Bionic's cmake is too old.
RUN pip install --upgrade pip cmake

# .travis.yml
RUN apt-get update && apt-get install --no-install-recommends -y \
 libconfig-dev \
 libgtest-dev \
 libopus-dev \
 libsodium-dev \
 libvpx-dev \
 ninja-build \
 pylint3 \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Set up travis user.
RUN groupadd -r -g 1000 travis \
 && useradd --no-log-init -r -g travis -u 1000 travis \
 && mkdir -p /src/workspace /home/travis \
 && chown travis:travis /home/travis
USER travis

# Set up environment.
ENV CC=gcc CXX=g++ \
PATH=/home/travis/.local/bin:$PATH \
TRAVIS_REPO_SLUG=TokTok/c-toxcore
