FROM golang:1.22-bookworm as builder

ENV CGO_ENABLED=0

WORKDIR /src
RUN --mount=target=/src,type=bind,source=. --mount=type=cache,target=/root/.cache/go-build go build -o /sshpiper-openpubkey -buildvcs=false -tags timetzdata

FROM farmer1992/sshpiperd:v1.2.7

ENV PLUGIN=sshpiper-openpubkey

COPY --from=builder /sshpiper-openpubkey /sshpiperd/plugins/
COPY --from=alpine:latest /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ADD web.tmpl /sshpiperd/plugins/

WORKDIR /sshpiperd/plugins/

EXPOSE 2222 3000

