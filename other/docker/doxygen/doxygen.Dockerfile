FROM toxchat/doxygen:latest AS build

RUN ["apk", "add", "--no-cache", \
 "gtest-dev", \
 "libconfig-dev", \
 "libsodium-dev", \
 "libvpx-dev", \
 "opus-dev"]

RUN git clone --depth=1 https://github.com/jothepro/doxygen-awesome-css.git /work/c-toxcore/doxygen-awesome-css

WORKDIR /work/c-toxcore
COPY . /work/c-toxcore/
RUN cmake . -B_build -GNinja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
 && echo "WARN_AS_ERROR = YES" >> Doxyfile \
 && sed -i -e 's/^non_null([^)]*) *//;s/^nullable([^)]*) *//' $(find . -name "*.[ch]") \
 && doxygen docs/Doxyfile

FROM nginx:alpine
COPY --from=build /work/c-toxcore/_docs/html/ /usr/share/nginx/html/
