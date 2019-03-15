package vault

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"

	"github.com/kauehmoreno/vault/safe"
)

type Vault struct {
	secretKey string
	filePath  string
	rw        io.ReadWriter
	encrypt   func(target string) (string, error)
	decrypt   func(target string) (string, error)
}

func New(secretKey, filePath string) Vault {
	enc, dec := safe.New(secretKey)
	return Vault{
		secretKey: secretKey,
		filePath:  filePath,
		encrypt:   enc,
		decrypt:   dec,
	}
}

func (v Vault) encryptByType(value interface{}) (string, error) {
	switch t := value.(type) {
	case string:
		return v.encrypt(t)
	case int:
		return v.encrypt(strconv.FormatInt(int64(t), 10))
	case int64:
		return v.encrypt(strconv.FormatInt(t, 10))
	case float64:
		number := strconv.FormatFloat(t, 'E', -1, 64)
		return v.encrypt(number)
	case []byte:
		return v.encrypt(string(t))
	default:
		return "", errors.New("Not implemented any case for this type")
	}
}

func (v *Vault) Load() error {
	f, err := os.OpenFile(v.filePath, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	js := make(map[string]interface{})
	if err := decoder.Decode(&js); err != nil {
		return err
	}
	content := make(map[string]interface{})
	for key, value := range js {
		encryptedKey, err := v.encrypt(key)
		if err != nil {
			return err
		}
		switch t := value.(type) {
		case []interface{}:
			items := make([]interface{}, len(t))
			for _, item := range t {
				data, err := v.encryptByType(item)
				if err != nil {
					return err
				}
				items = append(items, data)
			}
			content[encryptedKey] = items
		case map[string]interface{}:
			var (
				data, dval string
				err        error
			)
			for key, val := range t {
				data, err = v.encrypt(key)
				if err != nil {
					return err
				}
				dval, err = v.encryptByType(val)
				if err != nil {
					return err
				}
			}
			content[encryptedKey] = map[string]interface{}{data: dval}
		}
	}

	if err := f.Truncate(0); err != nil {
		return err
	}

	if _, err := f.Seek(0, 0); err != nil {
		return err
	}

	encoder := json.NewEncoder(f)
	return encoder.Encode(content)
}
