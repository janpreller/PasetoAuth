package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/o1egl/paseto"
	uuid "github.com/satori/go.uuid"

	"./pasetoauth"
	"golang.org/x/crypto/ed25519"
)

func main() {
	signKey := make([]byte, 32)
	rand.Read(signKey)

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatalf("Could not generate keypair:%+v\n", err)
	}

	p := pasetoauth.New(signKey, publicKey, privateKey)

	token := paseto.JSONToken{
		Jti:        uuid.Must(uuid.NewV4()).String(),
		IssuedAt:   time.Now(),
		Expiration: time.Now().Add(time.Hour * 72),
		Subject:    "Username",
		Issuer:     "Api Authorative",
		Audience:   "Api Users",
		NotBefore:  time.Now().Add(time.Second * 5),
	}
	token.Set("Custom-Claim", "Custom Value")

	footer := "Some Footer"

	encToken, err := p.Encrypt(token, footer)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Successfully encrypted Token:%+v\n", encToken)

	var decToken paseto.JSONToken
	var decFooter string
	err = p.Decrypt(encToken, &decToken, &decFooter)
	if err != nil {
		log.Fatalf("Could not decrypt Token: %+v\n", err)
	}

	fmt.Println("Decrypted Token:", decToken)
	fmt.Println("Decrypted Footer:", decFooter)

	r := chi.NewRouter()

	r.Use(p.Verfier)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Sup"))
	})
	http.ListenAndServe(":3000", r)

}
