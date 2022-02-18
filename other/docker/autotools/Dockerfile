################################################
# autotools-linux
FROM toxchat/nacl:latest

# Copy the sources and run the build.
COPY --chown=builder:builder . /home/builder/c-toxcore/
WORKDIR /home/builder/c-toxcore
RUN CC=gcc .github/scripts/autotools-linux
