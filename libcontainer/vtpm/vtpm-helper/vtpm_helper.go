// + build linux

package vtpmhelper

import (
	"fmt"
	"os"

	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/vtpm"

	"github.com/opencontainers/runtime-spec/specs-go"
)

// Create a VTPM
func CreateVTPM(spec *specs.Spec, config *configs.Config, vtpmdev *specs.VTPM, devnum int, uid int, gid int) error {

	vtpm, err := vtpm.NewVTPM(vtpmdev.Statepath, vtpmdev.TPMVersion, vtpmdev.CreateCertificates)
	if err != nil {
		return err
	}

	// Start the vTPM process; once stopped, the device pair will
	// also disappear
	err, createdStatepath := vtpm.Start()
	if err != nil {
		return err
	}

	hostdev := vtpm.GetTPMDevname()
	major, minor := vtpm.GetMajorMinor()

	device := &configs.Device{
		Type:        'c',
		Path:        fmt.Sprintf("/dev/tpm%d", devnum),
		Major:       int64(major),
		Minor:       int64(minor),
		Permissions: "rwm",
		FileMode:    0600,
		Allow:       true,
		Uid:         0,
		Gid:         0,
	}

	config.Devices = append(config.Devices, device)

	major_p := new(int64)
	*major_p = int64(major)
	minor_p := new(int64)
	*minor_p = int64(minor)

	ld := &specs.LinuxDeviceCgroup{
		Allow:  true,
		Type:   "c",
		Major:  major_p,
		Minor:  minor_p,
		Access: "rwm",
	}
	spec.Linux.Resources.Devices = append(spec.Linux.Resources.Devices, *ld)

	config.VTPMs = append(config.VTPMs, vtpm)

	if uid != 0 {
		// adapt ownership of the device since only root can access it
		if err := os.Chown(hostdev, uid, gid); err != nil {
			vtpm.Stop(createdStatepath)
			return err
		}
	}

	return nil
}

func DestroyVTPMs(config *configs.Config) {
	for _, vtpm := range config.VTPMs {
		vtpm.Stop(true)
	}
	config.VTPMs = make([]*vtpm.VTPM, 0)
}
