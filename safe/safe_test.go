package safe_test

import (
	"fmt"
	"math/rand"
	"strconv"
	"testing"

	"github.com/kauehmoreno/vault/safe"

	"github.com/stretchr/testify/suite"
)

type TestSafeSuite struct {
	suite.Suite
}

func TestSafeSuiteCase(t *testing.T) {
	suite.Run(t, new(TestSafeSuite))
}

func (s TestSafeSuite) TestEncryptAndDecryptingValue() {
	value := "http://mysql-host.host.com:3360"
	encrypt, decrypt := safe.New("key-to-encrypt")

	data, err := encrypt(value)
	s.Require().NoError(err)
	s.Require().NotEqual(data, value, "Value of encrypted data should not match with orignal one")
	nValue, err := decrypt(data)
	s.Require().NoError(err)
	s.Require().Equal(nValue, value, "Decrypted data should match with original one")
}

func (s TestSafeSuite) TestMultipleCallOfEncryptAndDecrypt() {
	words := []string{
		"a", "b", "c", "d",
		"e", "f", "g", "h",
		"i", "j", "k", "l",
		"m", "n", "o", "p",
		"q", "r", "s", "t",
		"u", "v", "x", "y", "z",
	}
	encrypt, decrypt := safe.New("n-key")
	for _, w := range words {
		data, err := encrypt(w)
		s.Require().NoError(err)
		s.Require().NotEqual(data, w, "Value of encrypted data should not match with orignal one")
		nValue, err := decrypt(data)
		s.Require().NoError(err)
		s.Require().Equal(nValue, w, "Decrypted data should match with original one")
	}
}

func (s TestSafeSuite) TestErroOnDecryptNotEncryptedData() {
	value := "http://mysql-host.host.com:3360"
	_, decrypt := safe.New("key-to-encrypt")
	result, err := decrypt(value)
	s.Require().Error(err, "Should throw error based on encoding/hex")
	s.Require().Empty(result, "Result must be empty")
}

func BenchmarkTestOfEncryptMultipleTime(b *testing.B) {
	encrypt, _ := safe.New("n-key")
	for i := 1; i <= 2048; i *= 2 {
		b.Run(fmt.Sprintf("[encrypt]%d\n", i), func(b *testing.B) {
			for n := 0; n <= b.N; n++ {
				expected := strconv.FormatInt(int64(n), 10)
				data, err := encrypt(expected)
				if err != nil || data == expected {
					b.FailNow()
				}
			}
		})
	}
}

func BenchmarkTestOfDecryptAndDecryptMultipleTime(b *testing.B) {
	encrypt, decrypt := safe.New("n-key")
	for i := 1; i <= 2048; i *= 2 {
		b.Run(fmt.Sprintf("[decrypt]%d\n", i), func(b *testing.B) {
			for n := 0; n <= b.N; n++ {
				expected := strconv.FormatInt(int64(n), 10)
				data, err := encrypt(expected)
				if err != nil || data == expected {
					b.FailNow()
				}
				result, err := decrypt(data)
				if err != nil || result != expected {
					b.FailNow()
				}
			}
		})
	}
}

func BenchmarkTestEncryptAndDecryptInParallel(b *testing.B) {
	encrypt, decrypt := safe.New("n-key")
	for i := 1; i <= 2048; i *= 2 {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				n := rand.Int63()
				expected := strconv.FormatInt(n, 10)
				data, err := encrypt(expected)
				if err != nil || data == expected {
					b.FailNow()
				}
				result, err := decrypt(data)
				if err != nil || result != expected {
					b.FailNow()
				}
			}
		})
	}
}
