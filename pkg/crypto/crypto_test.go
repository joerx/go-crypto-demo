package crypto

import (
	"crypto/rand"
	"io"
	"testing"
)

var passphrase = "streng_geheim"
var text = "mary had a little lamb"

func TestCanEncryptAndDecrypt(t *testing.T) {
	b, err := Encrypt([]byte(text), passphrase)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := Decrypt(b, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != text {
		t.Fatalf("Expected ciphertext to decrypt to \"%s\" but was \"%s\"", text, plain)
	}
}

func TestDecryptFailsWithInvalidPassphrase(t *testing.T) {
	b, err := Encrypt([]byte(text), passphrase)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Decrypt(b, passphrase+"_typo")
	if err == nil {
		t.Fatal("Expected decryption error but got none")
	}
}

func makeRandomBytes(len int) ([]byte, error) {
	data := make([]byte, len)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		return nil, err
	}
	return data, nil
}

func benchmarkEncrypt(b *testing.B, numBytes int) {
	data, err := makeRandomBytes(numBytes)
	if err != nil {
		b.Fatal(err)
	}
	for n := 0; n < b.N; n++ {
		if _, err := Encrypt(data, passphrase); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkDecrypt(b *testing.B, numBytes int) {
	data, err := makeRandomBytes(numBytes)
	if err != nil {
		b.Fatal(err)
	}
	cipherText, err := Encrypt(data, passphrase)
	if err != nil {
		b.Fatal(err)
	}
	for n := 0; n < b.N; n++ {
		_, err := Decrypt(cipherText, passphrase)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncrypt1000Bytes(b *testing.B) {
	benchmarkEncrypt(b, 1000)
}

func BenchmarkEncrypt10000Bytes(b *testing.B) {
	benchmarkEncrypt(b, 10000)
}

func BenchmarkDecrypt1000Bytes(b *testing.B) {
	benchmarkDecrypt(b, 1000)
}

func BenchmarkDecrypt10000Bytes(b *testing.B) {
	benchmarkDecrypt(b, 10000)
}
