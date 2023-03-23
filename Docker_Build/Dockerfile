##
## Build
##
FROM golang:alpine AS build
LABEL description="Build container - snmp-adapter"

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY *.go ./
RUN go build 

##
## Deploy
##
FROM alpine:latest as runtime
LABEL description="Runtime container - snmp-adapter"

COPY --from=build /app/snmp-adapter /usr/local/bin/snmp-adapter

ENTRYPOINT ["/usr/local/bin/snmp-adapter"]