package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/awnumar/memguard"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/util"
)

const GQSecurityParameter = 256
const algo = jwa.ES256

func generateCic(
	signer crypto.Signer,
) (*clientinstance.Claims, error) {
	// Use our signing key to generate a JWK key with the alg header set
	jwkKey, err := jwk.PublicKeyOf(signer)
	if err != nil {
		return nil, err
	}
	err = jwkKey.Set(jwk.AlgorithmKey, algo)
	if err != nil {
		return nil, err
	}

	// Use provided public key to generate client instance claims
	cic, err := clientinstance.NewClaims(jwkKey, map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate client instance claims: %w", err)
	}

	// Define our OIDC nonce as a commitment to the client instance claims
	// nonce, err := cic.Hash()
	// if err != nil {
	// 	return nil, fmt.Errorf("error getting nonce: %w", err)
	// }

	return cic, nil
}

func OidcAuth(
	idToken *memguard.LockedBuffer,
	cicToken []byte,
	Op client.OpenIdProvider,
) (*pktoken.PKToken, error) {

	headersB64, _, _, err := jws.SplitCompact(idToken.Bytes())
	if err != nil {
		return nil, fmt.Errorf("error getting original headers: %w", err)
	}

	headers := jws.NewHeaders()
	err = parseJWTSegment(headersB64, &headers)
	if err != nil {
		return nil, err
	}

	opKey, err := Op.PublicKey(context.Background(), headers)
	if err != nil {
		return nil, fmt.Errorf("error getting OP public key: %w", err)
	}

	// if signGQ {
	rsaPubKey := opKey.(*rsa.PublicKey)

	sv, err := gq.NewSignerVerifier(rsaPubKey, GQSecurityParameter)
	if err != nil {
		return nil, fmt.Errorf("error creating GQ signer: %w", err)
	}
	gqToken, err := sv.SignJWT(idToken.Bytes())
	if err != nil {
		return nil, fmt.Errorf("error creating GQ signature: %w", err)
	}
	idToken = memguard.NewBufferFromBytes(gqToken)
	// }

	// Combine our ID token and signature over the cic to create our PK Token
	pkt, err := pktoken.New(idToken.Bytes(), cicToken)
	if err != nil {
		return nil, fmt.Errorf("error creating PK Token: %w", err)
	}

	err = client.VerifyPKToken(context.Background(), pkt, Op)
	if err != nil {
		return nil, fmt.Errorf("error verifying PK Token: %w", err)
	}

	err = pkt.AddJKTHeader(opKey)
	if err != nil {
		return nil, fmt.Errorf("error adding JKT header: %w", err)
	}
	return pkt, nil
}

func parseJWTSegment(segment []byte, v any) error {
	segmentJSON, err := util.Base64DecodeForJWT(segment)
	if err != nil {
		return fmt.Errorf("error decoding segment: %w", err)
	}

	err = json.Unmarshal(segmentJSON, v)
	if err != nil {
		return fmt.Errorf("error parsing segment: %w", err)
	}

	return nil
}
