package main

import (
	"crypto"
	"encoding/pem"
	"fmt"

	"github.com/awnumar/memguard"
	"github.com/openpubkey/openpubkey/examples/ssh/sshcert"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"golang.org/x/crypto/ssh"
)

func generateSshCert(token []byte, signer crypto.Signer, cic *clientinstance.Claims, issuer string) ([]byte, []byte, error) {

	// Use the commitment nonce to complete the OIDC flow and get an ID token from the provider
	// idToken, err := Op.RequestTokens(context.Background(), string(nonce))
	idToken := memguard.NewBufferFromBytes(token)
	defer idToken.Destroy()

	// Sign over the payload from the ID token and client instance claims
	cicToken, err := cic.Sign(signer, algo, idToken.Bytes())
	if err != nil {
		return nil, nil, fmt.Errorf("error creating cic token: %w", err)
	}

	pkt, err := OidcAuth(idToken, cicToken, &oidcPiperOP{
		OIDCIssuer: issuer,
	})
	if err != nil {
		return nil, nil, err
	}

	cert, err := sshcert.New(pkt, []string{})
	if err != nil {
		return nil, nil, err
	}
	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, nil, err
	}

	signerMas, err := ssh.NewSignerWithAlgorithms(sshSigner.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoECDSA256})
	if err != nil {
		return nil, nil, err
	}

	sshCert, err := cert.SignCert(signerMas)
	if err != nil {
		return nil, nil, err
	}

	certBytes := ssh.MarshalAuthorizedKey(sshCert)
	seckeySsh, err := ssh.MarshalPrivateKey(signer, "openpubkey cert")
	if err != nil {
		return nil, nil, err
	}
	seckeySshBytes := pem.EncodeToMemory(seckeySsh)

	return seckeySshBytes, certBytes, nil
}
