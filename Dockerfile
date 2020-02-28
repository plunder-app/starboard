# syntax=docker/dockerfile:experimental

FROM golang:1.13-alpine as dev
RUN apk add --no-cache git ca-certificates
RUN adduser -D appuser
COPY . /src/
WORKDIR /src

ENV GO111MODULE=on
RUN --mount=type=cache,sharing=locked,id=gomod,target=/go/pkg/mod/cache \
    --mount=type=cache,sharing=locked,id=goroot,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -ldflags '-s -w -extldflags -static' -o starboard

FROM alpine:latest
COPY --from=dev /src/starboard /
RUN apk add --no-cache iptables
CMD ["./starboard"]