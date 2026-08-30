//go:build !darwin

package mcpclient

func platformCommandSearchDirectories() []string {
	return []string{"/usr/local/bin"}
}
