# based on https://github.com/AFLplusplus/AFLplusplus/blob/stable/Dockerfile

FROM ubuntu:20.04

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG DEBIAN_FRONTEND=noninteractive

ENV NO_ARCH_OPT 1

RUN apt-get update && \
    apt-get -y install --no-install-suggests --no-install-recommends \
    apt-transport-https \
    apt-utils \
    automake \
    bash-completion \
    bison flex \
    build-essential \
    ca-certificates \
    cmake \
    dialog \
    git \
    gnupg \
    gnuplot-nox \
    jupp \
    less \
    libglib2.0-dev \
    libpixman-1-dev \
    libsodium-dev \
    libtool libtool-bin \
    nano \
    ninja-build \
    parallel \
    python-is-python3 \
    python3 \
    python3-dev \
    python3-setuptools \
    screen \
    vim \
    wget \
    && rm -rf /var/lib/apt/lists/*

RUN echo "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-12 main" >> /etc/apt/sources.list && \
    wget -qO - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -

RUN echo "deb http://ppa.launchpad.net/ubuntu-toolchain-r/test/ubuntu focal main" >> /etc/apt/sources.list && \
    apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 1E9377A2BA9EF27F

RUN apt-get update && apt-get full-upgrade -y && \
    apt-get -y install --no-install-suggests --no-install-recommends \
    clang-12 \
    clang-tools-12 \
    g++-10 \
    gcc-10 \
    gcc-10-multilib \
    gcc-10-plugin-dev \
    gcc-multilib \
    gdb \
    lcov \
    libc++-12-dev \
    libc++1-12 \
    libc++abi-12-dev \
    libc++abi1-12 \
    libclang-12-dev \
    libclang-common-12-dev \
    libclang-cpp12 \
    libclang-cpp12-dev \
    libclang1-12 \
    liblld-12 \
    liblld-12-dev \
    liblldb-12 \
    liblldb-12-dev \
    libllvm12 \
    libomp-12-dev \
    libomp5-12 \
    lld-12 \
    lldb-12 \
    llvm-12 \
    llvm-12-dev \
    llvm-12-runtime \
    llvm-12-tools \
    && rm -rf /var/lib/apt/lists/*

RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-10 0
RUN update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-10 0

ENV LLVM_CONFIG=llvm-config-12
ENV AFL_SKIP_CPUFREQ=1
ENV AFL_TRY_AFFINITY=1
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

RUN git clone --depth=1 https://github.com/vanhauser-thc/afl-cov /afl-cov
WORKDIR /afl-cov
RUN make install

RUN git clone --depth=1 https://github.com/AFLplusplus/AFLplusplus /AFLplusplus
WORKDIR /AFLplusplus
RUN export CC=gcc-10 && export CXX=g++-10 && make install

RUN echo '. /etc/bash_completion' >> ~/.bashrc
RUN echo 'alias joe="joe --wordwrap --joe_state -nobackup"' >> ~/.bashrc
ENV IS_DOCKER="1"
ENV CMAKE_GENERATOR=Ninja
