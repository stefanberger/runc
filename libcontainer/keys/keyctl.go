// +build linux

package keys

import (
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

const KEYCTL_JOIN_SESSION_KEYRING = 1
const KEYCTL_SETPERM = 5
const KEYCTL_DESCRIBE = 6
const KEYCTL_LINK = 8
const KEYCTL_UNLINK = 9
const KEYCTL_RESTRICT_KEYRING = 29

const KEY_PARENT_SESSION = 0xfffffffd

type KeySerial uint32

func JoinSessionKeyring(name string) (KeySerial, error) {
	sessKeyId, err := unix.KeyctlJoinSessionKeyring(name)
	if err != nil {
		return 0, fmt.Errorf("could not create session key: %v", err)
	}
	return KeySerial(sessKeyId), nil
}

// ModKeyringPerm modifies permissions on a keyring by reading the current permissions,
// anding the bits with the given mask (clearing permissions) and setting
// additional permission bits
func ModKeyringPerm(ringId KeySerial, mask, setbits uint32) error {
	dest, err := unix.KeyctlString(unix.KEYCTL_DESCRIBE, int(ringId))
	if err != nil {
		return err
	}

	res := strings.Split(dest, ";")
	if len(res) < 5 {
		return fmt.Errorf("Destination buffer for key description is too small")
	}

	// parse permissions
	perm64, err := strconv.ParseUint(res[3], 16, 32)
	if err != nil {
		return err
	}

	perm := (uint32(perm64) & mask) | setbits

	if err := unix.KeyctlSetperm(int(ringId), perm); err != nil {
		return err
	}

	return nil
}

func CreateKeyring(name string, parentRing KeySerial) (KeySerial, error) {
        return AddKey("keyring", name, nil, 0, parentRing)
}

func AddKey(keytype, description string, payload []byte, plen int, ringId KeySerial) (KeySerial, error) {
        var (
                _keytype     *byte = nil
                _description *byte = nil
                _payload     *byte = nil
                err          error
        )

        if len(keytype) > 0 {
                _keytype, err = unix.BytePtrFromString(keytype)
                if err != nil {
                        return 0, err
                }
        }

        if len(description) > 0 {
                _description, err = unix.BytePtrFromString(description)
                if err != nil {
                        return 0, err
                }
        }

        if payload != nil {
                _payload = &payload[0]
        }

        id, _, error := unix.Syscall6(unix.SYS_ADD_KEY, uintptr(unsafe.Pointer(_keytype)), uintptr(unsafe.Pointer(_description)), uintptr(unsafe.Pointer(_payload)), uintptr(plen), uintptr(ringId), 0)
        if error != 0 {
                return 0, error
        }

	return KeySerial(id), nil
}

func Link(keyId, ringId KeySerial) (KeySerial, error) {
	id, err := unix.KeyctlInt(KEYCTL_LINK, int(keyId), int(ringId), 0, 0)
	return KeySerial(id), err
}

func Unlink(keyId, ringId KeySerial) (KeySerial, error) {
	id, err := unix.KeyctlInt(KEYCTL_UNLINK, int(keyId), int(ringId), 0, 0)
	return KeySerial(id), err
}

func RestrictKeyring(ringId, restrictRingId KeySerial) (KeySerial, error) {
	buffer := fmt.Sprintf("key_or_keyring:%d:chain", restrictRingId)
	_buffer, err := unix.BytePtrFromString(buffer)
	if err != nil {
		return 0, err
	}
	_type, err := unix.BytePtrFromString("asymmetric")
	if err != nil {
		return 0, err
	}
	id, _, error := unix.Syscall6(unix.SYS_KEYCTL, uintptr(KEYCTL_RESTRICT_KEYRING), uintptr(int(ringId)), uintptr(unsafe.Pointer(_type)), uintptr(unsafe.Pointer(_buffer)), 0, 0)
	if error != 0 {
		return 0, error
	}
	return KeySerial(id), nil
}
