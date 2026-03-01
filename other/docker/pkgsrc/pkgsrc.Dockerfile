FROM toxchat/pkgsrc:latest

WORKDIR /work
COPY . /work/c-toxcore-0.2.22
RUN ["tar", "zcf", "c-toxcore.tar.gz", "c-toxcore-0.2.22"]

WORKDIR /work/pkgsrc
COPY other/docker/pkgsrc/pkgsrc.patch /tmp/pkgsrc.patch
RUN ["patch", "-p1", "-i", "/tmp/pkgsrc.patch"]

WORKDIR /work/pkgsrc/chat/toxcore
RUN ["bmake", "clean"]
RUN ["bmake", "DISTFILES=c-toxcore.tar.gz", "DISTDIR=/work", "NO_CHECKSUM=yes"]
RUN ["bmake", "DISTFILES=c-toxcore.tar.gz", "DISTDIR=/work", "NO_CHECKSUM=yes", "install"]
