FROM toxchat/pkgsrc:latest

WORKDIR /work
COPY . /work/c-toxcore-0.2.18
RUN ["tar", "zcf", "c-toxcore.tar.gz", "c-toxcore-0.2.18"]

WORKDIR /work/pkgsrc/chat/toxcore
RUN ["bmake", "clean"]
RUN ["bmake", "DISTFILES=c-toxcore.tar.gz", "DISTDIR=/work", "NO_CHECKSUM=yes"]
RUN ["bmake", "install"]
