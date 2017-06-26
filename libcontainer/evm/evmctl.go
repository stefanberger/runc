// +build linux

package evmctl

import (
	"io/ioutil"

	keyctl "github.com/opencontainers/runc/libcontainer/keys"
)

// Load a key on a keyring identified by its Id
func LoadKeyOnKeyring(ringId keyctl.KeySerial, filename string) (keyctl.KeySerial, error) {
	key, err := ioutil.ReadFile(filename)
	if err != nil {
		return 0, err
	}

	serial, err := keyctl.AddKey("asymmetric", "", key, len(key), ringId)
	if err != nil {
		return 0, err
	}
	return keyctl.KeySerial(serial), nil
}

