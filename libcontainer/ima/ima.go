// +build linux

package ima

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/opencontainers/runc/libcontainer/evm"
	keyctl "github.com/opencontainers/runc/libcontainer/keys"
)

// object
type IMA struct {
	hasIMANS   bool
	sessRingId keyctl.KeySerial
	policy     []byte
	keys       [][]byte
}

// IMA related code

func checkIMANS() bool {
	_, err := os.Stat("/proc/self/ns/ima")

	return err == nil
}

func NewIMA(policy []byte, keys [][]byte, sessRingId keyctl.KeySerial) (*IMA, error) {
	return &IMA{
		hasIMANS:   checkIMANS(),
		sessRingId: sessRingId,
		policy:     policy,
		keys:       keys,
	}, nil
}

func (ima *IMA) applyPolicy(policy []byte) error {
	f, err := os.OpenFile("/sys/kernel/security/ima/policy", os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(policy)

	return err
}

// Apply the user-provided policy
func (ima *IMA) ApplyPolicy() error {
	if len(ima.policy) > 0 {
		if !ima.hasIMANS {
			return fmt.Errorf("IMA namespacing not supported by kernel")
		}
		return ima.applyPolicy(ima.policy)
	}
	return nil
}

// Apply the policy found inside the container, unless we had a policy
// given explicitly; if IMA namespacing is not supported it's not an error
func (ima *IMA) ApplyPolicyContainer() error {
	if ima.hasIMANS && len(ima.policy) == 0 {
		for _, path := range []string{"/etc/ima/ima-policy", "/etc/default/ima-policy", "/etc/sysconfig/ima-policy"} {
			policy, err := ioutil.ReadFile(path)
			if err == nil {
				return ima.applyPolicy(policy)
			}
		}
	}
	return nil
}

// create an _ima keyring underneath the parent keyring
func setupIMARing(parentRing keyctl.KeySerial) (keyctl.KeySerial, error) {
	if (parentRing == keyctl.KEY_PARENT_SESSION) {
		return 0, fmt.Errorf("Must have a proper parent keyring; cannot be 0xffffffff")
	}
	// for IMA to find _ima, we need UID search permissions on the
	// parent key ring which may not be set in case of userns
	if err := keyctl.ModKeyringPerm(parentRing, 0xffffffff, 0x80000); err != nil {
		return 0, err
	}
	return keyctl.CreateKeyring("_ima", parentRing)
}

// Given user-provided keys, load them on the IMA namespace specific keyring.
// If IMA namespacing is not supported, an error is returned.
func (ima *IMA) ApplyKeys() error {
	if len(ima.keys) > 0 {
		if !ima.hasIMANS {
			return fmt.Errorf("IMA namespacing not supported by kernel")
		}

		ringId, err := setupIMARing(ima.sessRingId)
		if err != nil {
			return err
		}

		for _, key := range ima.keys {
			tmpFile, err := ioutil.TempFile("", "swtpmkey")
			if err != nil {
				return fmt.Errorf("Could not create temp file for IMA key")
			}

			if _, err := tmpFile.Write(key); err != nil {
				os.Remove(tmpFile.Name())
				return fmt.Errorf("Could not write to IMA key temp file '%s': %v", tmpFile.Name(), err)
			}
			tmpFile.Close()

			// failing to load a key onto the keyring is not an error
			evmctl.LoadKeyOnKeyring(ringId, tmpFile.Name())

			os.Remove(tmpFile.Name())
		}
		// make the keyring read-only and have it kept that way
		return keyctl.ModKeyringPerm(ringId, ^uint32(0x24242424), 0)
	}

	return nil
}

// Apply keys found inside the container unless a key was explicity provided
func (ima *IMA) ApplyKeysContainer() error {
	if ima.hasIMANS && len(ima.keys) == 0 {
		dirname := "/etc/keys/ima"

		fileInfos, err := ioutil.ReadDir(dirname)
		if err != nil {
			// missing dir is not an error
			return nil
		}

		var ringId keyctl.KeySerial = 0

		for _, fileInfo := range fileInfos {
			if !fileInfo.IsDir() {
				if ringId == 0 {
					ringId, err = setupIMARing(ima.sessRingId)
					if err != nil {
						return err
					}
				}

				filename := fmt.Sprintf("%s/%s", dirname, fileInfo.Name())

				// failing to load a key onto the keyring is not an error
				evmctl.LoadKeyOnKeyring(ringId, filename)
			}
		}

		// make the keyring read-only and have it kept that way
		if err := keyctl.ModKeyringPerm(ringId, ^uint32(0x24242424), 0); err != nil {
			return err
		}
	}

	return nil
}

// Apply the provided policy and key
func (ima *IMA) ApplyKeysAndPolicy() error {
	if err := ima.ApplyKeys(); err != nil {
		return err
	}
	return ima.ApplyPolicy()
}

// Apply the policy and keys found inside the container
func (ima *IMA) ApplyKeysAndPolicyContainer() error {
	if err := ima.ApplyKeysContainer(); err != nil {
		return err
	}
	return ima.ApplyPolicyContainer()
}

