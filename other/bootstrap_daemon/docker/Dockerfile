###########################################################
# Builder image: we compile the code here (static build)
FROM alpine:3.11.5 AS build

RUN ["apk", "--no-cache", "add",\
 "build-base",\
 "cmake",\
 "linux-headers",\
 "libconfig-dev",\
 "libconfig-static",\
 "libsodium-dev",\
 "libsodium-static",\
 "ninja",\
 "python3"\
]

WORKDIR /src/c-toxcore

# Very selectively add files to the image, because we may have random stuff
# lying around. In particular, we don't need to rebuild the docker image when
# toxav changes or the Dockerfile changes down from the build.
COPY cmake cmake
COPY other/bootstrap_daemon/src other/bootstrap_daemon/src
COPY other/bootstrap_node_packets.[ch] other/
COPY other/DHT_bootstrap.c other/
COPY other/pkgconfig other/pkgconfig
COPY other/rpm other/rpm
COPY testing/misc_tools.[ch] testing/
COPY toxcore toxcore
COPY toxencryptsave toxencryptsave
COPY CMakeLists.txt so.version ./

RUN ["cmake", "-B_build", "-H.",\
 "-GNinja",\
 "-DCMAKE_BUILD_TYPE=Release",\
 "-DFULLY_STATIC=ON",\
 "-DBUILD_TOXAV=OFF",\
 "-DBOOTSTRAP_DAEMON=ON"\
]
RUN ["cmake", "--build", "_build", "--target", "install"]

# Verify checksum from dev-built binary, so we can be sure Docker Hub doesn't
# mess with your binaries.
COPY other/bootstrap_daemon/docker/tox-bootstrapd.sha256 other/bootstrap_daemon/docker/
RUN ["sha256sum", "/usr/local/bin/tox-bootstrapd"]
RUN ["sha256sum", "-c", "other/bootstrap_daemon/docker/tox-bootstrapd.sha256"]

# Remove all the example bootstrap nodes from the config file.
COPY other/bootstrap_daemon/tox-bootstrapd.conf other/bootstrap_daemon/
# hadolint ignore=SC2086,SC2154
RUN ["sed", "-i", "/^bootstrap_nodes = /,$d", "other/bootstrap_daemon/tox-bootstrapd.conf"]

# Add bootstrap nodes from https://nodes.tox.chat/.
COPY other/bootstrap_daemon/docker/get-nodes.py other/bootstrap_daemon/docker/
RUN ["other/bootstrap_daemon/docker/get-nodes.py", "other/bootstrap_daemon/tox-bootstrapd.conf"]

###########################################################
# Final image build: this is what runs the bootstrap node
FROM debian:buster-slim

COPY --from=build /usr/local/bin/tox-bootstrapd /usr/local/bin/
COPY --from=build /src/c-toxcore/other/bootstrap_daemon/tox-bootstrapd.conf /etc/tox-bootstrapd.conf
RUN ["useradd", "--home-dir", "/var/lib/tox-bootstrapd", "--create-home",\
 "--system", "--shell", "/sbin/nologin",\
 "--comment", "Account to run the Tox DHT bootstrap daemon",\
 "--user-group", "tox-bootstrapd"\
]
RUN ["chmod", "644", "/etc/tox-bootstrapd.conf"]
RUN ["chmod", "700", "/var/lib/tox-bootstrapd"]

WORKDIR /var/lib/tox-bootstrapd

USER tox-bootstrapd

ENTRYPOINT ["/usr/local/bin/tox-bootstrapd",\
 "--config", "/etc/tox-bootstrapd.conf",\
 "--log-backend", "stdout",\
 "--foreground"\
]

EXPOSE 443/tcp 3389/tcp 33445/tcp 33445/udp
