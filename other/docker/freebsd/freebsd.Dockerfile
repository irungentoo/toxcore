FROM toxchat/freebsd:latest

WORKDIR /work/c-toxcore
COPY . /work/c-toxcore/

RUN [".github/scripts/cmake-freebsd"]
