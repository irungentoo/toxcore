FROM ubuntu:22.04

RUN apt-get update && apt-get install --no-install-recommends -y \
 build-essential \
 ca-certificates \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY generate_event_c.cpp /src/
RUN ["g++", "generate_event_c.cpp", "-o", "generate_event_c"]
CMD ["./generate_event_c"]
