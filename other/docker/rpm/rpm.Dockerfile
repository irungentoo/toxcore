FROM toxchat/c-toxcore:sources AS sources
FROM fedora:39

RUN ["dnf", "install", "-y", \
 "cmake", \
 "g++", \
 "gcc", \
 "git", \
 "libconfig-devel", \
 "libsodium-devel", \
 "libvpx-devel", \
 "make", \
 "opus-devel", \
 "rpmdevtools", \
 "rpmlint", \
 "systemd-units"]

ARG PROJECT_VERSION=master
ARG PROJECT_COMMIT_ID=master
ARG PROJECT_COMMIT_ID_SHORT=master

COPY --from=sources /src/ /work/c-toxcore-${PROJECT_COMMIT_ID}
WORKDIR /work/c-toxcore-${PROJECT_COMMIT_ID}/other/rpm

RUN make toxcore.spec \
  PROJECT_VERSION="$PROJECT_VERSION" \
  PROJECT_COMMIT_ID="$PROJECT_COMMIT_ID" \
  PROJECT_COMMIT_ID_SHORT="$PROJECT_COMMIT_ID_SHORT" \
  PROJECT_GIT_ROOT="/work/c-toxcore-$PROJECT_COMMIT_ID_SHORT"

WORKDIR /work
RUN tar zcf "c-toxcore-${PROJECT_COMMIT_ID_SHORT}.tar.gz" "c-toxcore-${PROJECT_COMMIT_ID}" \
 && mv "c-toxcore-${PROJECT_COMMIT_ID_SHORT}.tar.gz" "c-toxcore-${PROJECT_COMMIT_ID}/other/rpm"
WORKDIR /work/c-toxcore-${PROJECT_COMMIT_ID}/other/rpm
RUN make srpm \
  PROJECT_VERSION="$PROJECT_VERSION" \
  PROJECT_COMMIT_ID="$PROJECT_COMMIT_ID" \
  PROJECT_COMMIT_ID_SHORT="$PROJECT_COMMIT_ID_SHORT" \
  PROJECT_GIT_ROOT="$PROJECT_GIT_ROOT"

# Build the binary rpms.
RUN rpmbuild --rebuild "toxcore-${PROJECT_VERSION}-1.fc39.src.rpm"

# Install them and try running the bootstrap daemon.
RUN rpm -i /root/rpmbuild/RPMS/x86_64/*.rpm
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN script tox-bootstrapd --help | grep Usage
