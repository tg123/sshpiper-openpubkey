package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
	"net/http"

	"github.com/awnumar/memguard"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/client"
	oidcclient "github.com/zitadel/oidc/v2/pkg/client"
)

type oidcPiperOP struct {
	OIDCIssuer string
}

var _ client.OpenIdProvider = (*oidcPiperOP)(nil)

func (a *oidcPiperOP) RequestTokens(ctx context.Context, cicHash string) (*memguard.LockedBuffer, error) {
	return nil, fmt.Errorf("not implemented")
}

func (a *oidcPiperOP) VerifyCICHash(ctx context.Context, idt []byte, expectedCICHash string) error {
	cicHash, err := client.ExtractClaim(idt, "nonce")
	if err != nil {
		return err
	}

	if cicHash != expectedCICHash {
		return fmt.Errorf("nonce claim doesn't match, got %q, expected %q", cicHash, expectedCICHash)
	}

	return nil
}

func (a *oidcPiperOP) Issuer() string {
	return a.OIDCIssuer
}

func (a *oidcPiperOP) PublicKey(ctx context.Context, headers jws.Headers) (crypto.PublicKey, error) {
	discConf, err := oidcclient.Discover(a.Issuer(), http.DefaultClient)
	if err != nil {
		return nil, fmt.Errorf("failed to call OIDC discovery endpoint: %w", err)
	}

	jwks, err := jwk.Fetch(ctx, discConf.JwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch to JWKS: %w", err)
	}

	kid := headers.KeyID()
	key, ok := jwks.LookupKeyID(kid)
	if !ok {
		return nil, fmt.Errorf("key %q isn't in JWKS", kid)
	}

	pubKey := new(rsa.PublicKey)
	err = key.Raw(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	return pubKey, err
}

func (a *oidcPiperOP) VerifyNonGQSig(ctx context.Context, idt []byte, expectedNonce string) error {
	return fmt.Errorf("not implemented")
}
