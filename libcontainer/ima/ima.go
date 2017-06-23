// +build linux

package ima

import (
	"fmt"
	"io/ioutil"
	"os"
)

// object
type IMA struct {
	hasIMANS bool
	policy   []byte
}

func checkIMANS() (bool) {
	_, err := os.Stat("/proc/self/ns/ima")

	return err == nil
}

func NewIMA(policy []byte) (*IMA, error) {
	return &IMA{
		hasIMANS: checkIMANS(),
		policy: policy,
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
		for _, path := range []string{"/etc/default/ima-policy", "/etc/sysconfig/ima-policy"} {
			policy, err := ioutil.ReadFile(path)
			if err == nil {
				return ima.applyPolicy(policy)
			}
		}
	}
	return nil
}

