ARG RUNTIME_IMAGE=gcr.io/linkerd-io/base:2019-02-19.01

## compile proxy-identity agent
FROM gcr.io/linkerd-io/go-deps:90ae17cf as golang
WORKDIR /go/src/github.com/linkerd/linkerd2
ENV CGO_ENABLED=0 GOOS=linux

COPY pkg/flags pkg/flags
COPY pkg/tls pkg/tls
COPY pkg/version pkg/version
RUN go build ./pkg/...

COPY proxy-identity proxy-identity
RUN CGO_ENABLED=0 GOOS=linux go install ./proxy-identity

## package runtime
FROM $RUNTIME_IMAGE as runtime
COPY LICENSE /linkerd/LICENSE
COPY --from=golang /go/bin/proxy-identity /bin/proxy-identity
ARG LINKERD_VERSION
ENV LINKERD_CONTAINER_VERSION_OVERRIDE=${LINKERD_VERSION}
ENTRYPOINT ["/bin/proxy-identity"]
