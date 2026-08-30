//go:build darwin

package mcpclient

func platformCommandSearchDirectories() []string {
	return []string{"/opt/homebrew/bin", "/usr/local/bin"}
}
