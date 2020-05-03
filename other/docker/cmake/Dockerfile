################################################
# cmake-linux
FROM localbuild/travis:1.0.0

# Copy minimal files to run "cmake-linux install", so we can avoid rebuilding
# astyle and other things when only source files change.
RUN mkdir -p /home/travis/build/c-toxcore /home/travis/cache
WORKDIR /home/travis/build/c-toxcore
COPY --chown=travis:travis c-toxcore/.travis/ /home/travis/build/c-toxcore/.travis/
RUN .travis/cmake-linux install

# Now copy the rest of the sources and run the build.
COPY --chown=travis:travis . /home/travis/build/
RUN .travis/cmake-linux script
