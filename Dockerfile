FROM golang:alpine

WORKDIR /go/src/github.com/PolarGeospatialCenter/inventory-dhcp-server

COPY . ./
RUN apk add make git
ENV GO111MODULE on
RUN make linux

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=0 /go/src/github.com/PolarGeospatialCenter/inventory-dhcp-server/bin/inventory-dhcp-server.linux /bin/inventory-dhcp-server

EXPOSE 67/udp
ENTRYPOINT ["/bin/inventory-dhcp-server"]