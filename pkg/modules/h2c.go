package modules

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/SentinelXofficial/sxel/pkg/core"
)

func h2cSettingsHeader() string {
	settings := make([]byte, 6*2)
	binary.BigEndian.PutUint16(settings[0:2], 0x3)
	binary.BigEndian.PutUint32(settings[2:6], 0x100)
	return base64.RawURLEncoding.EncodeToString(settings)
}

func ScanH2C(client *http.Client, cfg *core.Config, targetURL string) []core.ScanResult {
	u, err := url.Parse(targetURL)
	if err != nil || !strings.EqualFold(u.Scheme, "http") {
		return nil
	}
	host := u.Host
	if u.Port() == "" {
		host += ":80"
	}
	conn, err := net.DialTimeout("tcp", host, 8*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(8 * time.Second))

	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: %s\r\n\r\n",
		path, u.Host, cfg.UserAgent, h2cSettingsHeader())

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return nil
	}

	var finding *core.ScanResult
	fields := strings.Fields(statusLine)
	if len(fields) >= 2 && (fields[1] == "101" || fields[1] == "426") {
		finding = &core.ScanResult{
			Type: "h2c (cleartext HTTP/2) enabled", URL: targetURL,
			Method: "GET", Parameter: "transport",
			Payload: "Upgrade: h2c", Severity: "MEDIUM",
			Evidence:  "server answered the h2c upgrade (" + fields[1] + ")",
			Timestamp: time.Now(),
		}
		fmt.Printf("  [H2C] %s upgrade answered %s\n", targetURL, fields[1])
	}
	if finding != nil {
		return []core.ScanResult{*finding}
	}
	return nil
}
