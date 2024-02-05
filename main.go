package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openpubkey/openpubkey/util"
	"github.com/sethvargo/go-limiter/memorystore"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

const errMsgPipeApprove = "ok"
const errMsgBadUpstream = "bad upstream"

func main() {
	gin.DefaultWriter = os.Stderr

	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "openpubkey",
		Usage: "sshpiperd openpubkey plugin",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "webaddr",
				Value:   ":3000",
				EnvVars: []string{"SSHPIPERD_OPENPUBKEY_WEBADDR"},
			},
			&cli.StringFlag{
				Name:     "baseurl",
				EnvVars:  []string{"SSHPIPERD_OPENPUBKEY_BASEURL"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "clientid",
				EnvVars:  []string{"SSHPIPERD_OPENPUBKEY_CLIENTID"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "clientsecret",
				EnvVars:  []string{"SSHPIPERD_OPENPUBKEY_CLIENTSECRET"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "issuerurl",
				EnvVars:  []string{"SSHPIPERD_OPENPUBKEY_ISSUERURL"},
				Required: true,
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {

			store, err := newSessionstoreMemory()
			if err != nil {
				return nil, err
			}

			baseurl := c.String("baseurl")
			issuerurl := c.String("issuerurl")

			w, err := newWeb(oidcconfig{
				clientId:     c.String("clientid"),
				clientSecret: c.String("clientsecret"),
				baseurl:      baseurl,
				issuer:       issuerurl,
			}, store)

			if err != nil {
				return nil, err
			}

			go func() {
				panic(w.Run(c.String("webaddr")))
			}()

			limiter, err := memorystore.New(&memorystore.Config{
				Tokens:      3,
				Interval:    time.Minute,
				SweepMinTTL: time.Minute * 5,
			})

			if err != nil {
				return nil, err
			}

			return &libplugin.SshPiperPluginConfig{
				KeyboardInteractiveCallback: func(conn libplugin.ConnMetadata, client libplugin.KeyboardInteractiveChallenge) (u *libplugin.Upstream, err error) {
					session := conn.UniqueID()
					lasterr := store.GetSshError(session)

					// retry
					if lasterr != nil {

						if *lasterr != errMsgBadUpstream {

							// retry with no err set, using default err
							if *lasterr == "" {
								*lasterr = errMsgBadUpstream
							}

							_, _ = client("", fmt.Sprintf("connection failed %v", *lasterr), "", false)
							store.SetSshError(session, errMsgBadUpstream) // set already notified
						}

						return nil, fmt.Errorf("retry not allowed")
					}

					// new session
					store.SetSshError(session, "") // set waiting for approval

					defer func() {
						if err != nil {
							store.SetSshError(session, err.Error())
						}
					}()

					signer, err := util.GenKeyPair(algo)
					if err != nil {
						return nil, err
					}

					cic, err := generateCic(signer)
					if err != nil {
						return nil, err
					}

					nonce, err := cic.Hash()
					if err != nil {
						return nil, err
					}

					store.SetNonce(session, nonce)

					_, _ = client("", fmt.Sprintf("please open %v/pipe/%v with your browser to verify (timeout 1m)", baseurl, session), "", false)

					st := time.Now()

					for {

						if time.Now().After(st.Add(time.Second * 60)) {
							return nil, fmt.Errorf("timeout waiting for approval")
						}

						lasterr := store.GetSshError(session)
						if lasterr != nil && *lasterr != "" {
							return nil, fmt.Errorf(*lasterr)
						}

						upstream, _ := store.GetUpstream(session)
						if upstream == "" {
							time.Sleep(time.Millisecond * 100)
							continue
						}

						token, _ := store.GetSecret(session)
						if token == nil {
							return nil, fmt.Errorf("secret expired")
						}

						seckeySshBytes, certBytes, err := generateSshCert(token, signer, cic, issuerurl)
						if err != nil {
							return nil, err
						}

						host, port, user, err := parseUpstream(upstream)
						if err != nil {
							return nil, err
						}

						_, _ = client("", fmt.Sprintf("session approved, connecting to %v", upstream), "", false)

						return &libplugin.Upstream{
							Host:          host,
							Port:          int32(port),
							UserName:      user,
							Auth:          libplugin.CreatePrivateKeyAuth(seckeySshBytes, certBytes),
							IgnoreHostKey: true,
						}, nil
					}
				},
				NewConnectionCallback: func(conn libplugin.ConnMetadata) error {
					ip, _, _ := net.SplitHostPort(conn.RemoteAddr())
					_, _, _, ok, err := limiter.Take(context.Background(), ip)
					if err != nil {
						return err
					}

					if !ok {
						return fmt.Errorf("too many connections")
					}

					return nil
				},
				UpstreamAuthFailureCallback: func(conn libplugin.ConnMetadata, method string, err error, allowmethods []string) {
					session := conn.UniqueID()
					store.SetSshError(session, err.Error())
					store.DeleteSession(session, true)
				},
				PipeStartCallback: func(conn libplugin.ConnMetadata) {
					session := conn.UniqueID()
					store.SetSshError(session, errMsgPipeApprove)
					store.DeleteSession(session, true)
				},
				PipeErrorCallback: func(conn libplugin.ConnMetadata, err error) {
					session := conn.UniqueID()
					store.DeleteSession(session, false)

					ip, _, _ := net.SplitHostPort(conn.RemoteAddr())
					limiter.Burst(context.Background(), ip, 1)
				},
			}, nil
		},
	})
}

func parseUpstream(data string) (host string, port int, user string, err error) {
	host = strings.TrimSpace(data)

	t := strings.SplitN(host, "@", 2)

	if len(t) > 1 {
		user = t[0]
		host = t[1]
	}

	host, port, err = libplugin.SplitHostPortForSSH(host)
	return
}
