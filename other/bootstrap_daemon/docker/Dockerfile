FROM debian:jessie

# get all deps
RUN apt-get update && apt-get install -y \
      build-essential \
      libtool \
      autotools-dev \
      automake \
      checkinstall \
      check \
      git \
      yasm \
      libsodium-dev \
      libconfig-dev \
      python3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# install toxcore and daemon
WORKDIR /root/
RUN git clone https://github.com/irungentoo/toxcore
WORKDIR /root/toxcore/
RUN ./autogen.sh
RUN ./configure --enable-daemon
RUN make -j`nproc`
RUN make install -j`nproc`
RUN ldconfig

WORKDIR /root/toxcore/other/bootstrap_daemon/

# add new user
RUN useradd --home-dir /var/lib/tox-bootstrapd --create-home \
      --system --shell /sbin/nologin \
      --comment "Account to run Tox's DHT bootstrap daemon" \
      --user-group tox-bootstrapd
RUN chmod 700 /var/lib/tox-bootstrapd

RUN cp tox-bootstrapd.conf /etc/tox-bootstrapd.conf

# remove all the example bootstrap nodes from the config file
RUN N=-1 && \
    while grep -q "bootstrap_nodes =" /etc/tox-bootstrapd.conf; \
    do \
      head -n $N tox-bootstrapd.conf > /etc/tox-bootstrapd.conf; \
      N=$((N-1)); \
    done

# add bootstrap nodes from https://nodes.tox.chat/
RUN python3 docker/get-nodes.py >> /etc/tox-bootstrapd.conf

USER tox-bootstrapd

ENTRYPOINT /usr/local/bin/tox-bootstrapd \
             --config /etc/tox-bootstrapd.conf \
             --log-backend stdout \
             --foreground

EXPOSE 443 3389 33445
EXPOSE 33445/udp
