# How to create a sshd with openpubkey + google oidc public key

The Dockerfile is an example of how to create a sshd server that uses openpubkey to verify the public key of the user. The public key is fetched from google's oidc endpoint. 

The example is based on [openpubkey ssh exmaple](https://github.com/openpubkey/openpubkey/blob/02dbac9a36c7f7e02f41e242386e7e0056e6a957/examples/ssh/opkssh/cli.go#L146)


## Build your image

```
docker build -t opk-sshd --build-arg=GOOGLE_EMAIL=<YOUR GOOGLE EMAIL> .
```

e.g.

```
docker build -t opk-sshd --build-arg=GOOGLE_EMAIL=bob@gmail.com .
```

## Run your image

```
docker run -d opk-sshd
```

## Test with opk.sshpiper.com

 1. open <https://opk.sshpiper.com/>
 1. add your public ip address of opk-sshd container, remember add `root` as user. for example, `root@1.2.3.4` if your public ip is `1.2.3.4`. this will help sshpiper to route using root user to target container
 1. `ssh opk.sshpiper.com`
 1. click link to openpubkey, and login with your google account
 1. click approve button, `↑` , to ssh