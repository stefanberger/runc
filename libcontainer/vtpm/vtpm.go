// + build linux

package vtpm

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"github.com/sirupsen/logrus"
)

// object
type VTPM struct {
	// The path where the TPM emulator writes the TPM state to
	StatePath string `json:"statePath"`

	// Whether to create a certificate for the VTPM
	CreateCerts bool `json:"createCerts"`

	// Version of the TPM
	Vtpmversion string `json:"vtpmversion"`

	// The user under which to run the TPM emulator
	user string

	// The TPM device number as returned from /dev/vtpmx ioctl
	Tpm_dev_num uint32 `json:"tpm_dev_num"`

	// The backend file descriptor
	fd int32

	// The major number of the created device
	major uint32

	// The minor number of the created device
	minor uint32
}

// ioctl
type vtpm_proxy_new_dev struct {
	flags       uint32
	tpm_dev_num uint32
	fd          int32
	major       uint32
	minor       uint32
}

const (
	ILLEGAL_FD           = -1
	VTPM_DEV_NUM_INVALID = 0xffffffff

	VTPM_PROXY_IOC_NEW_DEV = 0xc014a100

	VTPM_VERSION_1_2 = "1.2"
	VTPM_VERSION_2   = "2"

	VTPM_FLAG_TPM2 = 1
)

func ioctl(fd, cmd, msg uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, cmd, msg)
	if errno != 0 {
		err := errno
		return err
	}

	return nil
}

func vtpmx_ioctl(cmd, msg uintptr) error {
	vtpmx, err := os.Open("/dev/vtpmx")
	if err != nil {
		logrus.Warnf("Could not open /dev/vtpmx: %v", err)
		return err
	}
	defer vtpmx.Close()

	if err := ioctl(uintptr(vtpmx.Fd()), cmd, msg); err != nil {
		return fmt.Errorf("VTPM: vtpmx ioctl failed: %v", err)
	}

	return nil
}

// Create a new VTPM object
//
// @statepath: directory where the vTPM's state will be written into
// @vtpmversion: The TPM version
// @createcerts: whether to create certificates for the vTPM (on first start)
//
// After successful creation of the object the Start() method can be called
func NewVTPM(statepath, vtpmversion string, createcerts bool) (*VTPM, error) {
	if len(statepath) == 0 {
		return nil, fmt.Errorf("Missing required statpath for vTPM.")
	}

	if len(vtpmversion) == 0 {
		vtpmversion = VTPM_VERSION_1_2
	}
	if vtpmversion != VTPM_VERSION_1_2 && vtpmversion != VTPM_VERSION_2 {
		return nil, fmt.Errorf("Unsupported VTPM version '%s'.", vtpmversion)
	}

	exec.Command("modprobe", "tpm_vtpm_proxy").Run()
	if _, err := os.Stat("/dev/vtpmx"); err != nil {
		return nil, fmt.Errorf("VTPM device driver not available.")
	}

	return &VTPM{
		Tpm_dev_num: VTPM_DEV_NUM_INVALID,
		user:        "tss",
		StatePath:   statepath,
		Vtpmversion: vtpmversion,
		CreateCerts: createcerts,
	}, nil
}

func (vtpm *VTPM) createDev() error {
	var (
		vtpm_proxy_new_dev vtpm_proxy_new_dev
	)

	if vtpm.Tpm_dev_num != VTPM_DEV_NUM_INVALID {
		logrus.Info("Device already exists")
		return nil
	}

	if vtpm.Vtpmversion == VTPM_VERSION_2 {
		vtpm_proxy_new_dev.flags = VTPM_FLAG_TPM2
	}

	err := vtpmx_ioctl(VTPM_PROXY_IOC_NEW_DEV, uintptr(unsafe.Pointer(&vtpm_proxy_new_dev)))
	if err != nil {
		return err
	}

	vtpm.Tpm_dev_num = vtpm_proxy_new_dev.tpm_dev_num
	vtpm.fd = vtpm_proxy_new_dev.fd
	vtpm.major = vtpm_proxy_new_dev.major
	vtpm.minor = vtpm_proxy_new_dev.minor

	return nil
}

func (vtpm *VTPM) getPidFile() string {
	return path.Join(vtpm.StatePath, "swtpm.pid")
}

func (vtpm *VTPM) getLogFile() string {
	return path.Join(vtpm.StatePath, "swtpm.log")
}

// getPidFromFile: Get the PID from the PID file
func (vtpm *VTPM) getPidFromFile() (int, error) {
	d, err := ioutil.ReadFile(vtpm.getPidFile())
	if err != nil {
		return -1, err
	}
	if len(d) == 0 {
		return -1, fmt.Errorf("Empty pid file")
	}

	pid, err := strconv.Atoi(string(d))
	if err != nil {
		return -1, fmt.Errorf("Could not parse pid from file: %s", string(d))
	}
	return pid, nil
}

// waitForPidFile: wait for the PID file to appear and read the PID from it
func (vtpm *VTPM) waitForPidFile(loops int) (int, error) {
	for loops >= 0 {
		pid, err := vtpm.getPidFromFile()
		if pid > 0 && err == nil {
			return pid, nil
		}
		time.Sleep(time.Millisecond * 100)
		loops -= 1
	}
	logrus.Error("PID file did not appear")
	return -1, fmt.Errorf("swtpm's pid file did not appear")
}

func (vtpm *VTPM) shutdown() error {
	var err error = nil

	if vtpm.Tpm_dev_num != VTPM_DEV_NUM_INVALID && vtpm.Vtpmversion == VTPM_VERSION_2 {
		devname := vtpm.GetTPMDevname()
		dev, err := os.OpenFile(devname, os.O_RDWR, 0666)
		if err != nil {
			logrus.Errorf("Could not open %s: %v", devname, err)
			return err
		}
		defer dev.Close()

		sd := []byte{0x80, 0x01, 0x00, 0x00, 0x00, 0x0c,
			0x00, 0x00, 0x01, 0x45, 0x00, 0x00}
		n, err := dev.Write(sd)
		if err != nil || n != len(sd) {
			logrus.Errorf("Could not write shutdown to %s: %v", devname, err)
		}
	}
	return err
}

// stopByPidFile: Stop the vTPM by its PID file
func (vtpm *VTPM) stopByPidFile() error {

	vtpm.shutdown()

	pid, err := vtpm.getPidFromFile()
	if err != nil {
		return err
	}

	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}

	err = p.Signal(syscall.SIGTERM)

	return err
}

func (vtpm *VTPM) modifyModePath(dirPath string, mask, set os.FileMode) error {
	for {
		fileInfo, err := os.Stat(dirPath)
		if err != nil {
			return err
		}
		if !fileInfo.IsDir() {
			continue
		}

		mode := (fileInfo.Mode() & mask) | set
		if err := os.Chmod(dirPath, mode); err != nil {
			return err
		}

		dirPath = filepath.Dir(dirPath)
		if dirPath == "/" {
			break
		}
	}
	return nil
}

// Delete the directory where the TPM emaultor writes its state into
func (vtpm *VTPM) DeleteStatePath() error {
	return os.RemoveAll(vtpm.StatePath)
}

// Create the TPM directory where it writes its state into; make it accessible
// to the container user, who may be a remapped to non-root on the host
//
// This method returns true; in case the path was created because it did
// not exist before.
func (vtpm *VTPM) createStatePath() (bool, error) {
	if _, err := os.Stat(vtpm.StatePath); err == nil {
		return false, nil
	}

	user, err := user.Lookup(vtpm.user)
	if err != nil {
		return false, fmt.Errorf("User '%s' not available: %v", vtpm.user, err)
	}

	uid, err := strconv.Atoi(user.Uid)
	if err != nil {
		return false, fmt.Errorf("Error parsing Uid %s: %v", user.Uid, err)
	}

	gid, err := strconv.Atoi(user.Gid)
	if err != nil {
		return false, fmt.Errorf("Error parsing Gid %s: %v", user.Gid, err)
	}

	if err := os.MkdirAll(vtpm.StatePath, 0770); err != nil {
		return false, fmt.Errorf("Could not create directory %s: %v", vtpm.StatePath, err)
	}

	if err := os.Chown(vtpm.StatePath, uid, gid); err != nil {
		return false, fmt.Errorf("Could not change ownership of directory %s: %v", vtpm.StatePath, err)
	}

	if uid != 0 {
		if err := vtpm.modifyModePath(vtpm.StatePath, 0777, 0011); err != nil {
			return false, fmt.Errorf("Could not chmod path to %s: %v", vtpm.StatePath, err)
		}
	}

	return true, nil
}

func (vtpm *VTPM) setup(createCerts bool) error {
	cmd := exec.Command("swtpm_setup", "--tpm-state", vtpm.StatePath, "--createek",
		"--runas", vtpm.user, "--logfile", vtpm.getLogFile())
	if createCerts {
		cmd.Args = append(cmd.Args, "--create-ek-cert", "--create-platform-cert", "--lock-nvram")
	}

	if vtpm.Vtpmversion == VTPM_VERSION_2 {
		cmd.Args = append(cmd.Args, "--tpm2")
	}

	// need to explicitly set TMPDIR
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "TMPDIR=/tmp")

	output, err := cmd.CombinedOutput()
	if err != nil {
		logrus.Errorf("swtpm_setup failed: %s", string(output))
		vtpm.CloseServer()
		return fmt.Errorf("swtpm_setup failed: %s\nlog: %s", string(output), vtpm.ReadLog())
	}

	return nil
}

// waitForTPMDevice: Wait for /dev/tpm%d to appear and while doing that
//  check whether the swtpm is still alive.
func (vtpm *VTPM) waitForTPMDevice(loops int) error {
	devname := vtpm.GetTPMDevname()
	pidfile := vtpm.getPidFile()

	for loops >= 0 {
		if _, err := os.Stat(pidfile); err != nil {
			logrus.Errorf("swtpm process has terminated")
			return err
		}

		if _, err := os.Stat(devname); err == nil {
			return nil
		}
		time.Sleep(time.Millisecond * 100)
		loops -= 1
	}
	return fmt.Errorf("TPM device %s did not appear", devname)
}

// Start the vTPM
//
// - ensure any still running vTPM, which wrote its PID into a file in its state path, is terminated
//   the swtpm will, upon normal termination, remove its PID file
// - setup the state path
// - if the state path was created ( = swtpm runs for the first time) also create the certificates
// - create the device pair
// - start the swtpm process
// - run swtpm_bios on it to initiailize the vTPM
//   - if return code is 129, restart the vTPM to activate it and run swtpm_bios again
//
// After this method ran successfully, the TPM device (/dev/tpm%d) is available for use
func (vtpm *VTPM) Start() (error, bool) {
	looped := false

	vtpm.stopByPidFile()

	createdStatePath, err := vtpm.createStatePath()
	if err != nil {
		vtpm.CloseServer()
		return err, false
	}

	if createdStatePath {
		if err := vtpm.setup(vtpm.CreateCerts); err != nil {
			vtpm.DeleteStatePath()
			return err, false
		}
	}

again:
	if err := vtpm.createDev(); err != nil {
		if createdStatePath {
			vtpm.DeleteStatePath()
		}
		return err, false
	}

	tpmname := vtpm.GetTPMDevname()
	fdstr := fmt.Sprintf("%d", vtpm.fd)
	tpmstate := fmt.Sprintf("dir=%s", vtpm.StatePath)
	pidfile := fmt.Sprintf("file=%s", vtpm.getPidFile())
	logfile := fmt.Sprintf("file=%s", vtpm.getLogFile())

	cmd := exec.Command("swtpm", "chardev", "--tpmstate", tpmstate, "--daemon", "--fd", fdstr, "--pid", pidfile, "--log", logfile, "--runas", vtpm.user)
	if vtpm.Vtpmversion == VTPM_VERSION_2 {
		cmd.Args = append(cmd.Args, "--tpm2")
	}
	cmd.Args = append(cmd.Args, "--locality", "reject-locality-4,allow-set-locality", "--flags", "not-need-init")
	file := os.NewFile(uintptr(vtpm.fd), "[vtpm]")
	cmd.ExtraFiles = append(cmd.ExtraFiles, file)

	output, err := cmd.CombinedOutput()
	if err != nil {
		logrus.Errorf("swtpm failed on fd %d: %s", vtpm.fd, string(output))
		vtpm.CloseServer()
		if createdStatePath {
			vtpm.DeleteStatePath()
		}
		return fmt.Errorf("swtpm failed on fd %d: %s\nlog: %s", vtpm.fd, string(output), vtpm.ReadLog()), false
	}

	_, err = vtpm.waitForPidFile(10)
	if err != nil {
		vtpm.Stop(createdStatePath)
		return err, false
	}

	if err := vtpm.waitForTPMDevice(50); err != nil {
		vtpm.Stop(createdStatePath)
		return err, false
	}

	cmd = exec.Command("swtpm_bios", "-n", "-cs", "-u", "--tpm-device", tpmname)
	if vtpm.Vtpmversion == VTPM_VERSION_2 {
		cmd.Args = append(cmd.Args, "--tpm2")
	} else {
		// make sure the TPM 1.2 is activated
		cmd.Args = append(cmd.Args, "-ea")
	}

	output, err = cmd.CombinedOutput()
	if err != nil {
		logrus.Errorf("swtpm_bios failed on %s: %s", tpmname, string(output))
		vtpm.Stop(createdStatePath)
		if exiterr, ok := err.(*exec.ExitError); ok {
			// exit code was != 0
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				logrus.Errorf("swtpm_bios exit Status: %d", status.ExitStatus())

				// Error code 129 means that the swtpm needs a reset
				// to be activated again
				if status.ExitStatus() == 129 {
					if !looped {
						goto again
					}
					return fmt.Errorf("vTPM on %s seems broken since it would need another reset", tpmname), false
				}
			}
		}
		return fmt.Errorf("swtpm_bios failed on %s: %s\nlog: %s", tpmname, string(output), vtpm.ReadLog()), false
	}

	return nil, createdStatePath
}

// Stop a running vTPM; to be called after Start()
// After this method ran, Start() can be called again
func (vtpm *VTPM) Stop(deleteStatePath bool) error {

	err := vtpm.stopByPidFile()

	vtpm.CloseServer()

	vtpm.Tpm_dev_num = VTPM_DEV_NUM_INVALID

	if deleteStatePath {
		vtpm.DeleteStatePath()
	}

	return err
}

// Get the TPM device name; this method can be called after Start()
func (vtpm *VTPM) GetTPMDevname() string {
	return fmt.Sprintf("/dev/tpm%d", vtpm.Tpm_dev_num)
}

func (vtpm *VTPM) GetTPMDevNum() uint32 {
	return vtpm.Tpm_dev_num
}

// Get the major and minor numbers of the created device;
// This method can be called after Start()
func (vtpm *VTPM) GetMajorMinor() (uint32, uint32) {
	return vtpm.major, vtpm.minor
}

// Read the vTPM's log file and return the contents as a string
// This method can be called after Start()
func (vtpm *VTPM) ReadLog() string {
	output, err := ioutil.ReadFile(vtpm.getLogFile())
	if err != nil {
		return ""
	}
	return string(output)
}

// Close the server side file descriptor;
// This method can be called after Start()
func (vtpm *VTPM) CloseServer() error {

	// FIXME: runc has fd = 0 since it's not a daemon
	// so we skip the closing if fd == 0 as well, even though this is not correct
	if vtpm.fd != ILLEGAL_FD && vtpm.fd != 0 {
		os.NewFile(uintptr(vtpm.fd), "[vtpm]").Close()
		vtpm.fd = ILLEGAL_FD
	}
	return nil
}
