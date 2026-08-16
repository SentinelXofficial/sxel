package proxy

import (
	"regexp"
)

var awsKeyRe = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
var privKeyRe = regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`)
var pwRe = regexp.MustCompile(`(?i)(password|passwd|pwd|api[_-]?key|secret|token)\s*[:=]\s*["'][^"']{6,}["']`)
