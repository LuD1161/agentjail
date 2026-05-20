//go:build linux && !amd64 && !arm64

package seccomp

// nativeAudit == 0 sentinels "unsupported arch"; nativeArch() in
// profile_linux.go turns that into ErrUnsupportedArch at Apply()-time.
// Keeping the package compilable on every Linux GOARCH means a future
// riscv64 / loong64 port is one new tables_linux_<arch>.go file away.
const nativeAudit uint32 = 0

var nativeSyscalls = map[string]uint32{}
