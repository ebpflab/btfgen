package btfgen

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/cilium/ebpf/btf"
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/unix"
)

var (
	btfSpec *btf.Spec
	once    sync.Once
)

func initialize() error {
	// If the kernel exposes BTF; nothing to do
	_, err := btf.LoadKernelSpec()
	if err == nil {
		return nil
	}

	info, err := getOSInfo()
	if err != nil {
		return err
	}

	// architecture naming is a mess:
	// - Golang uses amd64 and arm64
	// - btfhub uses x86_64 and arm64
	// - bpf2go uses x86 and arm64
	goarch := runtime.GOARCH
	if goarch == "amd64" {
		goarch = "x86"
	}

	btfFile := fmt.Sprintf("btfhub/%s/%s/%s/%s.btf",
		info.ID, info.VersionID, info.Arch, info.Kernel)

	file, err := btfHub.ReadFile(btfFile)
	if err != nil {
		return fmt.Errorf("reading %s BTF file %w", btfFile, err)
	}

	s, err := btf.LoadSpecFromReader(bytes.NewReader(file))
	if err != nil {
		return fmt.Errorf("loading BTF spec: %w", err)
	}

	btfSpec = s
	return nil
}

// GetBTFSpec returns the BTF spec with kernel information for the current kernel version. If the
// kernel exposes BTF information or if the BTF for this kernel is not found, it returns nil.
func GetBTFSpec() *btf.Spec {
	once.Do(func() {
		err := initialize()
		if err != nil {
			log.Warn().Msg(fmt.Sprintf("Failed to initialize BTF: %v", err))
		}
	})
	return btfSpec
}

type osInfo struct {
	ID        string
	VersionID string
	Arch      string
	Kernel    string
}

var (
	HostRoot   string
	HostProcFs string
)

func init() {
	// Initialize HostRoot and HostProcFs
	HostRoot = os.Getenv("HOST_ROOT")
	if HostRoot == "" {
		HostRoot = "/"
	}
	HostProcFs = filepath.Join(HostRoot, "/proc")
}

func getOSInfo() (*osInfo, error) {
	osInfo := &osInfo{}

	file, err := os.Open(filepath.Join(HostRoot, "/etc/os-release"))
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		switch parts[0] {
		case "ID":
			osInfo.ID = parts[1]
		case "VERSION_ID":
			osInfo.VersionID = strings.Trim(parts[1], "\"")
		}
	}

	if osInfo.ID == "" || osInfo.VersionID == "" {
		return nil, fmt.Errorf("os-release file is incomplete")
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning file: %w", err)
	}

	uts := &unix.Utsname{}
	if err := unix.Uname(uts); err != nil {
		return nil, fmt.Errorf("calling uname: %w", err)
	}

	osInfo.Kernel = unix.ByteSliceToString(uts.Release[:])
	osInfo.Arch = unix.ByteSliceToString(uts.Machine[:])

	return osInfo, nil
}
