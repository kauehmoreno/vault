package safe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// New return to client both encrypt and decrypt method which must define a target value to be
// encrypted or decrypted based on secret key declared
func New(key string) (func(target string) (string, error), func(target string) (string, error)) {
	return func(target string) (string, error) {
			return encrypt(key, target)
		}, func(target string) (string, error) {
			return decrypt(key, target)
		}
}

func encrypt(key string, target string) (string, error) {
	cipherText := make([]byte, aes.BlockSize+len(target))
	iv := cipherText[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	block, err := cipherBlock(key)
	if err != nil {
		return "", err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], []byte(target))
	return fmt.Sprintf("%x", cipherText), nil
}

func decrypt(key string, target string) (string, error) {
	cipherText, err := hex.DecodeString(target)
	if err != nil {
		return "", err
	}
	if len(cipherText) < aes.BlockSize {
		return "", errors.New("cipher text is too short")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	block, err := cipherBlock(key)
	if err != nil {
		return "", err
	}
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)
	return string(cipherText), nil
}

func cipherBlock(key string) (cipher.Block, error) {
	hash := md5.New()
	io.WriteString(hash, key)
	return aes.NewCipher(hash.Sum(nil))
}
