package proxy

import (
	"net"
	"strings"
)

func parseIPHost(host string) net.IP {
	h := stripPort(host)
	return net.ParseIP(h)
}

func stripPort(host string) string {
	if strings.HasPrefix(host, "[") && strings.Contains(host, "]") {
		h := host[1:strings.Index(host, "]")]
		if len(host) > strings.Index(host, "]")+1 && host[strings.Index(host, "]")+1] == ':' {
			return h
		}
		return h
	}
	if net.ParseIP(host) != nil {
		return host
	}
	if i := strings.LastIndex(host, ":"); i > 0 {
		return host[:i]
	}
	return host
}
