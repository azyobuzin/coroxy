FROM golang:1.13 AS build
RUN mkdir -p /go/src/github.com/azyobuzin/coroxy
WORKDIR /go/src/github.com/azyobuzin/coroxy
COPY *.go .
RUN go get && CGO_ENABLED=0 go build -o /coroxy

FROM scratch
COPY --from=build /coroxy /coroxy
ENTRYPOINT ["/coroxy"]
