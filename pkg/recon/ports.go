package recon

import (
	"bufio"
	"net"
	"os"
	"strings"
	"time"
)

func PortOpen(host string, port int, timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	addr := net.JoinHostPort(host, itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func ReadWordlistFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var words []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		w := strings.TrimSpace(strings.ToLower(sc.Text()))
		if w != "" {
			words = append(words, w)
		}
	}
	return words, sc.Err()
}
