## compile controller services
FROM gcr.io/linkerd-io/go-deps:8ae929bd as golang
WORKDIR /go/src/github.com/linkerd/linkerd2
COPY controller/gen controller/gen
COPY pkg pkg
COPY controller controller
COPY api api

# use `install` so that we produce multiple binaries
RUN CGO_ENABLED=0 GOOS=linux go install ./pkg/...
RUN CGO_ENABLED=0 GOOS=linux go install ./api/...

## package runtime
FROM scratch
ENV PATH=$PATH:/go/bin
COPY LICENSE /linkerd/LICENSE
COPY --from=golang /go/bin /go/bin

ARG LINKERD_VERSION
ENV LINKERD_CONTAINER_VERSION_OVERRIDE=${LINKERD_VERSION}
