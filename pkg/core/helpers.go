package core

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type HeaderList []string

func (h *HeaderList) String() string {
	return strings.Join(*h, ", ")
}

func (h *HeaderList) Set(value string) error {
	*h = append(*h, value)
	return nil
}

func ParseHeaderLine(line string) (key, value string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	key = strings.TrimSpace(parts[0])
	value = strings.TrimSpace(parts[1])
	if key == "" {
		return "", "", false
	}
	return key, value, true
}

func BuildHeaders(args HeaderList, headersFile string) (map[string]string, error) {
	headers := map[string]string{}
	for _, h := range args {
		if k, v, ok := ParseHeaderLine(h); ok {
			headers[k] = v
		}
	}
	if headersFile != "" {
		f, err := os.Open(headersFile)
		if err != nil {
			return nil, fmt.Errorf("opening %s: %w", headersFile, err)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			if k, v, ok := ParseHeaderLine(scanner.Text()); ok {
				headers[k] = v
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("reading %s: %w", headersFile, err)
		}
	}
	return headers, nil
}

func ReadURLList(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var urls []string
	seen := map[string]bool{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !seen[line] {
			seen[line] = true
			urls = append(urls, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return urls, nil
}
