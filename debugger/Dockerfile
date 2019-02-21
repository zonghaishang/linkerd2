FROM gcr.io/linkerd-io/base:2017-10-30.01
RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump \
    iproute2 \
    strace \
    lsof \
    tar \
    net-tools && \
    rm -rf /var/lib/apt/lists/*
ENTRYPOINT [ "bin/sh" ]
