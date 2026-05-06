package sniff

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
)

func ExtractHTTPHost(buf []byte) (host, port string, err error) {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(buf)))
	if err != nil {
		return "", "", fmt.Errorf("parse HTTP request: %w", err)
	}
	if req.Host == "" {
		return "", "", fmt.Errorf("HTTP Host header missing")
	}

	host, port, splitErr := net.SplitHostPort(req.Host)
	if splitErr != nil {
		return req.Host, "", nil
	}

	return host, port, nil
}
