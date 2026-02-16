FROM golang:1.25 AS build

ARG VERSION

WORKDIR /src

COPY ./ ./

RUN cd cmd/auth-server && CGO_ENABLED=0 GOAMD64=v2 go build -ldflags "-X main.version=${VERSION}"


FROM debian:trixie-slim

WORKDIR /

COPY --from=build "/src/cmd/auth-server/auth-server" "/bin/auth-server"

EXPOSE 6080

VOLUME /etc/auth-server

ENTRYPOINT ["/bin/auth-server"]
CMD ["-config", "/etc/auth-server/auth-server.jsonc"]
