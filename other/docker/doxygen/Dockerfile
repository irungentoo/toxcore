FROM alpine:latest AS build

ENV LANG=en_US.UTF-8 \
    LANGUAGE=en_US.UTF-8 \
    LC_CTYPE=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8

RUN apk add --no-cache doxygen git graphviz \
 && git clone --depth=1 https://github.com/jothepro/doxygen-awesome-css.git /work/doxygen-awesome-css
WORKDIR /work
COPY . /work/
RUN cat .doxygen.conf > doxygen.conf \
 && echo "WARN_AS_ERROR = YES" >> doxygen.conf \
 && doxygen doxygen.conf

FROM nginx:alpine
COPY --from=build /work/_docs/html/ /usr/share/nginx/html/
