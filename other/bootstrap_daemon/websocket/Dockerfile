# Stage 1 - Compile websockify.
FROM toxchat/bootstrap-node:latest AS tox
FROM golang:1.23-alpine3.21 AS websockify

COPY websockify /work/websockify
RUN cd /work/websockify && go mod download github.com/gorilla/websocket && go install

# Stage 2 - Create the run-time image with bootstrap daemon and websockify.
FROM alpine:latest

RUN addgroup -S tox && adduser -SDH -G tox tox

COPY --from=websockify /go/bin/websockify /usr/local/bin/
COPY --from=tox /usr/local /usr/local/
COPY --from=tox /etc/tox-bootstrapd.conf /etc/
COPY entrypoint.sh /

RUN mkdir -p /var/lib/tox-bootstrapd/ /var/run/tox-bootstrapd/ \
 && chown tox:tox /var/lib/tox-bootstrapd/ /var/run/tox-bootstrapd/
# Public Key: 122837CCDD474DD1183A83152164D51427044B3EAAA52ED683F6BA602568673B
COPY keys /var/lib/tox-bootstrapd/
USER tox

# Use this to generate a keys file:
#RUN /usr/local/bin/tox-bootstrapd --config /etc/tox-bootstrapd.conf --log-backend stdout \
# && sleep 1

COPY tox-bootstrapd.conf /etc/

WORKDIR /web
CMD ["/entrypoint.sh"]
