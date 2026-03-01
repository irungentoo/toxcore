FROM toxchat/haskell:hs-cimple AS cimple
FROM ubuntu:22.04

COPY --from=cimple /bin/cimplefmt /bin/
WORKDIR /work
ENTRYPOINT ["/bin/cimplefmt"]
