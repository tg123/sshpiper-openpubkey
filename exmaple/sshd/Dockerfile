FROM golang:1.21 as builder

ENV CGO_ENABLED=0

WORKDIR /src
RUN git clone https://github.com/openpubkey/openpubkey.git /src
WORKDIR /src
RUN --mount=type=cache,target=/root/.cache/go-build go build -o /opkssh ./examples/ssh/opkssh 

# FROM lscr.io/linuxserver/openssh-server:latest
FROM linuxkit/sshd:7e71b29a4223436c741d73149f880f7bf5d44dd7
ARG GOOGLE_EMAIL

RUN test -n "$GOOGLE_EMAIL"


RUN mkdir -p /etc/opk

COPY --from=builder /opkssh /etc/opk/opkssh

RUN echo "AuthorizedKeysCommand /etc/opk/opkssh ver %u %k %t" >> /etc/ssh/sshd_config
RUN echo "AuthorizedKeysCommandUser root" >> /etc/ssh/sshd_config
RUN echo "LogLevel DEBUG3" >> /etc/ssh/sshd_config


RUN echo "$GOOGLE_EMAIL root" > /etc/opk/policy
RUN chmod 600 /etc/opk/policy