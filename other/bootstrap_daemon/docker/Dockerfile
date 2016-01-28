FROM debian:jessie

WORKDIR /tmp/tox

RUN export BUILD_PACKAGES="\
      build-essential \
      libtool \
      autotools-dev \
      automake \
      checkinstall \
      check \
      git \
      yasm \
      libsodium-dev \
      python3" && \
    export RUNTIME_PACKAGES="\
      libconfig-dev \
      libsodium13" && \
# get all deps
    apt-get update && apt-get install -y $BUILD_PACKAGES $RUNTIME_PACKAGES && \
# install toxcore and daemon
    git clone https://github.com/irungentoo/toxcore && \
    cd toxcore && \
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
    N=-1 && \
    while grep -q "bootstrap_nodes =" /etc/tox-bootstrapd.conf; \
    do \
      head -n $N other/bootstrap_daemon/tox-bootstrapd.conf > /etc/tox-bootstrapd.conf; \
      N=$((N-1)); \
    done && \
# add bootstrap nodes from https://nodes.tox.chat/
    python3 other/bootstrap_daemon/docker/get-nodes.py >> /etc/tox-bootstrapd.conf && \
    export AUTO_ADDED_PACKAGES="$(apt-mark showauto)" && \
    apt-get remove --purge -y $BUILD_PACKAGES $AUTO_ADDED_PACKAGES && \
    apt-get install -y $RUNTIME_PACKAGES && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    cd / && \
    rm -rf /tmp/*

WORKDIR /

USER tox-bootstrapd

ENTRYPOINT /usr/local/bin/tox-bootstrapd \
             --config /etc/tox-bootstrapd.conf \
             --log-backend stdout \
             --foreground

EXPOSE 443 3389 33445
EXPOSE 33445/udp
