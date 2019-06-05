package main

import (
	"encoding/base64"
	"fmt"
	"github.com/joerx/go-crypto-demo/pkg/crypto"
	"log"
)

func main() {
	fmt.Println("Hello world")

	text := "Mary had a little lamb"
	passphrase := "streng geheim"

	b, err := crypto.Encrypt([]byte(text), passphrase)
	if err != nil {
		log.Fatal(err)
	}

	b64 := base64.StdEncoding.EncodeToString(b)

	fmt.Printf("Encrypted data: %s\n", b64)

	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		log.Fatal(err)
	}

	plainBytes, err := crypto.Decrypt(data, passphrase)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Decrypted data: %s\n", string(plainBytes))
}
