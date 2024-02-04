package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

const templatefile = "web.tmpl"

type contextKey string

const nonceKey contextKey = "nonce"

type web struct {
	sessionstore sessionstore

	provider rp.RelyingParty

	r *gin.Engine
}

type oidcconfig struct {
	clientId     string
	clientSecret string
	baseurl      string
	issuer       string
}

func newWeb(config oidcconfig, sessionstore sessionstore) (*web, error) {
	r := gin.Default()
	r.LoadHTMLFiles(templatefile)

	provider, err := rp.NewRelyingPartyOIDC(
		config.issuer,
		config.clientId,
		config.clientSecret,
		fmt.Sprintf("%s/login-callback", config.baseurl),
		[]string{"openid", "profile", "email"},
		rp.WithVerifierOpts(
			rp.WithNonce(func(ctx context.Context) string { return ctx.Value(nonceKey).(string) }),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating provider: %w", err)
	}

	w := &web{
		r:            r,
		sessionstore: sessionstore,
		provider:     provider,
	}

	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, templatefile, gin.H{})
	})
	r.GET("/pipe/:session", w.pipe)
	r.GET("/lasterr/:session", w.lasterr)
	r.GET("/login-callback", w.loginCallback)
	r.POST("/approve", w.approve)

	return w, nil
}

func (w *web) Run(addr string) error {
	return w.r.Run(addr)
}

func (w *web) approve(c *gin.Context) {
	session := c.PostForm("session")
	if session == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"status": "error",
			"error":  "missing session",
		})
		return
	}

	upstream := c.PostForm("upstream")
	if upstream == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"status": "error",
			"error":  "missing upstream",
		})
		return
	}

	w.sessionstore.SetUpstream(session, upstream)

	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
	})
}

func (w *web) lasterr(c *gin.Context) {
	session := c.Param("session")

	errmsg := w.sessionstore.GetSshError(session)
	if errmsg == nil {
		c.JSON(http.StatusOK, gin.H{
			"status": "unknown",
		})
		return
	}

	if *errmsg == "" {
		c.JSON(http.StatusOK, gin.H{
			"status": "unknown",
		})
		return
	}

	if *errmsg == errMsgPipeApprove {
		c.JSON(http.StatusOK, gin.H{
			"status": "approved",
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"status": "error",
			"error":  *errmsg,
		})
	}
}

func (w *web) pipe(c *gin.Context) {
	session := c.Param("session")

	if session == "" {
		c.AbortWithError(http.StatusBadRequest, fmt.Errorf("missing session"))
		return
	}

	nonce, _ := w.sessionstore.GetNonce(session)
	if nonce == nil {
		c.AbortWithError(http.StatusBadRequest, fmt.Errorf("session expired"))
		return
	}

	url := rp.AuthURL(session, w.provider, rp.AuthURLOpt(rp.WithURLParam("nonce", string(nonce))))

	c.Redirect(http.StatusTemporaryRedirect, url)
}

func (w *web) loginCallback(c *gin.Context) {
	session := c.Query("state")
	if session == "" {
		c.AbortWithError(http.StatusBadRequest, fmt.Errorf("missing session"))
		return
	}

	nonce, _ := w.sessionstore.GetNonce(session)
	if nonce == nil {
		c.AbortWithError(http.StatusBadRequest, fmt.Errorf("session expired"))
		return
	}

	rp.CodeExchangeHandler(func(_ http.ResponseWriter, _ *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], _ string, _ rp.RelyingParty) {
		w.sessionstore.SetSecret(session, []byte(tokens.IDToken))
		c.HTML(http.StatusOK, templatefile, gin.H{
			"session": session,
		})
	}, w.provider)(c.Writer, c.Request.WithContext(context.WithValue(c.Request.Context(), nonceKey, string(nonce))))
}
