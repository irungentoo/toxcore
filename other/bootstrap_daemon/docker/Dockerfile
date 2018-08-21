FROM debian:stretch-slim

WORKDIR /tmp/tox

RUN export BUILD_PACKAGES="\
      build-essential \
      libtool \
      autotools-dev \
      automake \
      checkinstall \
      git \
      yasm \
      libsodium-dev \
      libconfig-dev \
      python3" && \
    export RUNTIME_PACKAGES="\
      libconfig9 \
      libsodium18" && \
# get all deps
    apt-get update && apt-get install -y $BUILD_PACKAGES $RUNTIME_PACKAGES && \
# install toxcore and daemon
    git clone https://github.com/TokTok/c-toxcore && \
    cd c-toxcore && \
    ./autogen.sh && \
    ./configure --enable-daemon && \
    make -j`nproc` && \
    make install -j`nproc` && \
    ldconfig && \
# add new user
    useradd --home-dir /var/lib/tox-bootstrapd --create-home \
      --system --shell /sbin/nologin \
      --comment "Account to run Tox's DHT bootstrap daemon" \
      --user-group tox-bootstrapd && \
    chmod 700 /var/lib/tox-bootstrapd && \
    cp other/bootstrap_daemon/tox-bootstrapd.conf /etc/tox-bootstrapd.conf && \
# remove all the example bootstrap nodes from the config file
    sed -i '/^bootstrap_nodes = /,$d' /etc/tox-bootstrapd.conf && \
# add bootstrap nodes from https://nodes.tox.chat/
    python3 other/bootstrap_daemon/docker/get-nodes.py >> /etc/tox-bootstrapd.conf && \
# perform cleanup
    apt-get remove --purge -y $BUILD_PACKAGES && \
    apt-get clean && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/* && \
    cd / && \
    rm -rf /tmp/*

WORKDIR /var/lib/tox-bootstrapd

USER tox-bootstrapd

ENTRYPOINT /usr/local/bin/tox-bootstrapd \
             --config /etc/tox-bootstrapd.conf \
             --log-backend stdout \
             --foreground

EXPOSE 443/tcp 3389/tcp 33445/tcp 33445/udp
