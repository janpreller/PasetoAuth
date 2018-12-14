package pasetoauth

import (
	"context"
	"net/http"
	"strings"

	"github.com/o1egl/paseto"
	"golang.org/x/crypto/ed25519"
)

type Paseto struct {
	symmetricKey []byte
	publicKey    ed25519.PublicKey
	privateKey   ed25519.PrivateKey
	v2           *paseto.V2
}

func New(symmetricKey []byte, pubKey ed25519.PublicKey, privKey ed25519.PrivateKey) *Paseto {
	return &Paseto{
		symmetricKey: symmetricKey,
		publicKey:    pubKey,
		privateKey:   privKey,
		v2:           paseto.NewV2(),
	}
}

func (p *Paseto) Encrypt(token interface{}, footer interface{}) (encToken string, err error) {
	encToken, err = p.v2.Encrypt(p.symmetricKey, token, footer)
	if err != nil {
		return "", err
	}
	return
}

func (p *Paseto) Decrypt(token string, dstToken interface{}, dstFooter interface{}) (err error) {
	err = p.v2.Decrypt(token, p.symmetricKey, dstToken, dstFooter)
	return
}

func (p *Paseto) Sign() {

}

func (p *Paseto) Verify() {

}

func (p *Paseto) Verfier(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := r.Header.Get("Authorization")
		var decToken paseto.JSONToken
		var decFooter string
		if len(bearer) > 7 && strings.ToUpper(bearer[0:6]) == "BEARER" {
			err := p.Decrypt(bearer[7:], &decToken, &decFooter)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			c := r.Context()
			c = context.WithValue(c, "token", decToken)
			next.ServeHTTP(w, r.WithContext(c))
			return
		}
		http.Error(w, "Err", http.StatusUnauthorized)
	})
}
