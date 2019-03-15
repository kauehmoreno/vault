package vault_test

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/kauehmoreno/vault"
	"github.com/stretchr/testify/suite"
)

type TestVaultSuite struct {
	suite.Suite
}

func TestVaultSuiteCase(t *testing.T) {
	suite.Run(t, new(TestVaultSuite))
}
func (s TestVaultSuite) SetupTest() {
	if err := createFile("file-test.json", nil); err != nil {
		s.Require().FailNow(fmt.Sprintf("Error on create file %v", err))
	}
}

func (s TestVaultSuite) TestLoadVault() {
	defer deleteFile("file-test.json")
	vault := vault.New("secret-key", "file-test.json")
	err := vault.Load()
	s.Require().NoError(err)
}

func (s TestVaultSuite) TestNestedMapValue() {
	nestedContent := struct {
		DB struct {
			Host struct {
				Write string `json:"write"`
				Read  string `json:"read"`
			} `json:"host"`
		} `json:"db"`
	}{struct {
		Host struct {
			Write string `json:"write"`
			Read  string `json:"read"`
		} `json:"host"`
	}{struct {
		Write string `json:"write"`
		Read  string `json:"read"`
	}{"mysql-writer", "mysql-reader"}}}
	createFile("file-test-nested.json", nestedContent)
	vault := vault.New("my-secret-key", "file-test-nested.json")
	err := vault.Load()
	fmt.Println(err)
	s.Require().Error(err)
}

func createFile(fileName string, content interface{}) error {
	if content == nil {
		content = struct {
			DB struct {
				Host string `json:"host"`
			} `json:"db"`
		}{struct {
			Host string `json:"host"`
		}{"content to be encrypted"}}
	}
	f, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer f.Close()
	encoder := json.NewEncoder(f)
	return encoder.Encode(content)
}

func deleteFile(fileName string) error {
	return os.Remove(fileName)
}
