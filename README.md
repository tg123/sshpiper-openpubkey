# sshpiper + openpubkey

This is an sshpiper plugin that authenticates upstream using [openpubkey](https://github.com/openpubkey/openpubkey).
Openpubkey plugin does not store any or require private key to upstream server. It generates a private key on the fly with Openpubkey and uses it to authenticate to upstream server. 


## The sshd accepts openpubkey

see [example/sshd](example/sshd/README.md) for how to create a sshd with openpubkey + google oidc public key

## Run with docker compose

Get your Google OIdc client id and secret from [Google Cloud Console](https://console.cloud.google.com/apis/credentials)

 * `SSHPIPERD_OPENPUBKEY_CLIENTID` is the client id of your oidc client
 * `SSHPIPERD_OPENPUBKEY_CLIENTSECRET` is the client secret of your oidc client


```bash
docker compose up -d
```

docker-compose.yml

```yaml
version: '2'
services:
  nginx-proxy:
    image: jwilder/nginx-proxy
    restart: always
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /etc/nginx/vhost.d
      - /usr/share/nginx/html
      - /var/run/docker.sock:/tmp/docker.sock:ro
      - certs:/etc/nginx/certs:ro
    environment:
      DEFAULT_HOST: opk.sshpiper.com
  letsencrypt:
    image: jrcs/letsencrypt-nginx-proxy-companion
    restart: always
    volumes_from:
      - nginx-proxy
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - certs:/etc/nginx/certs:rw
  opk:
    image: farmer1992/sshpiper-openpubkey
    restart: always
    ports:
      - "22:2222"
    expose:
      - "3000"
    environment:
      - GIN_MODE=release
      - SSHPIPERD_LOGIN_GRACE_TIME=1m
      - VIRTUAL_HOST=opk.sshpiper.com
      - VIRTUAL_PORT=3000
      - LETSENCRYPT_HOST=opk.sshpiper.com
      - LETSENCRYPT_EMAIL=farmer1992@gmail.com
      - SSHPIPERD_OPENPUBKEY_BASEURL=https://opk.sshpiper.com
      - SSHPIPERD_OPENPUBKEY_CLIENTID=xxxxxxxxxxxxxxxxxx.apps.googleusercontent.com
      - SSHPIPERD_OPENPUBKEY_CLIENTSECRET=xxxxxxxxxxxxxxx
      - SSHPIPERD_OPENPUBKEY_ISSUERURL=https://accounts.google.com
      - SSHPIPERD_SERVER_KEY_DATA=<base64 of server key>

volumes:
  certs:
```