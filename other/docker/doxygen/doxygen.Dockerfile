FROM toxchat/c-toxcore:sources AS sources
FROM alpine:3.19.0 AS build

ENV LANG=en_US.UTF-8 \
    LANGUAGE=en_US.UTF-8 \
    LC_CTYPE=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8

RUN apk add --no-cache doxygen git graphviz texlive \
 && git clone --depth=1 https://github.com/jothepro/doxygen-awesome-css.git /work/doxygen-awesome-css
WORKDIR /work
COPY --from=sources /src/ /work/
COPY docs/Doxyfile /work/Doxyfile
RUN echo "WARN_AS_ERROR = YES" >> Doxyfile \
 && sed -i -e 's/^non_null([^)]*) *//;s/^nullable([^)]*) *//' $(find . -name "*.[ch]") \
 && doxygen Doxyfile

FROM nginx:alpine
COPY --from=build /work/_docs/html/ /usr/share/nginx/html/
