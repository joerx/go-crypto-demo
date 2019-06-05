package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"io"
)

// Create 32 bit hash for given passphrase to use as cipher key
// MD5 is insecure but we're not storing the output anywhere so it's fine
func createHash(passphrase string) []byte {
	hasher := md5.New()
	hasher.Write([]byte(passphrase))
	return hasher.Sum(nil)
	//return hex.EncodeToString(hasher.Sum(nil))
}

func newGCMWithAES(passphrase string) (cipher.AEAD, error) {
	// hash passphrase to make sure it is 32 bytes long
	key := createHash(passphrase)
	block, err  := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Galois Counter Mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm, nil
}

// Encrypt takes the given data and encrypts it using AWS 256 cipher and Galois/Counter cipher mode
func Encrypt(data []byte, passphrase string) ([]byte, error) {
	// Galois Counter Mode
	gcm, err := newGCMWithAES(passphrase)
	if err != nil {
		return nil, err
	}
	// Random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt, prefix with nonce
	ct := gcm.Seal(nonce, nonce, data, nil)
	return ct, nil
}

func Decrypt(data []byte, passphrase string) ([]byte, error) {
	// Galois Counter Mode
	gcm, err := newGCMWithAES(passphrase)
	if err != nil {
		return nil, err
	}

	ns := gcm.NonceSize()
	nonce, cipherText := data[:ns], data[ns:]

	plain, err := gcm.Open(nil, nonce, cipherText, nil )
	if err != nil {
		return nil, err
	}

	return plain, nil
}

func DecryptString(data string, passphrase string) (string, error) {
	plain, err := Decrypt([]byte(data), passphrase)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
