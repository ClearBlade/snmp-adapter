#docker build -f ../docker_build/Dockerfile -t snmpAdapter --target runtime  ../..

FROM alpine:latest
LABEL description="Runtime container - SNMP-Adapter"

#Copy the SNMP Adapter binary into the image
COPY ./snmpAdapter /usr/local/bin/snmpAdapter

RUN apk --no-cache --update add ca-certificates

ENTRYPOINT ["/usr/local/bin/snmpAdapter"]