package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

var allowlist = map[string]bool{
	"http":        true,
	"https":       true,
	"file":        true,
	"data":        true,
	"view-source": true,
}

type Scheme string

const (
	http  Scheme = "http"
	https Scheme = "https"
	file  Scheme = "file"
	data  Scheme = "data"
)

type URL struct {
	Scheme     Scheme
	Host       string
	Port       int
	Path       string
	ViewSource bool
}

var socketCache = struct {
	mu    sync.Mutex
	conns map[string]net.Conn
}{conns: make(map[string]net.Conn)}

func NewURL(rawURL string) (*URL, error) {
	u := &URL{}
	if strings.HasPrefix(rawURL, "view-source:") {
		u.ViewSource = true
		rawURL = strings.TrimPrefix(rawURL, "view-source:")
	}

	if strings.HasPrefix(rawURL, "data:") {
		u.Scheme = data
		u.Path = strings.TrimPrefix(rawURL, "data:")
		return u, nil
	}

	parts := strings.SplitN(rawURL, "://", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid URL: missing scheme")
	}
	scheme := parts[0]
	rest := parts[1]

	if !allowlist[scheme] {
		return nil, fmt.Errorf("unsupported scheme: %q", scheme)
	}

	if u.Scheme == file {
		u.Path = "/" + rest
		return u, nil
	}

	if !strings.Contains(rest, "/") {
		rest = rest + "/"
	}

	slashIdx := strings.Index(rest, "/")
	host := rest[:slashIdx]
	path := rest[slashIdx:]

	var port int
	switch scheme {
	case "http":
		port = 80
	case "https":
		port = 443
	}

	if strings.Contains(host, ":") {
		hostParts := strings.SplitN(host, ":", 2)
		host = hostParts[0]
		p, err := strconv.Atoi(hostParts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid port: %q", hostParts[1])
		}
		port = p
	}

	u.Scheme = Scheme(scheme)
	u.Host = host
	u.Port = port
	u.Path = path

	return u, nil
}

func (u *URL) Request(ctx context.Context) (string, error) {
	switch u.Scheme {
	case file:
		body, err := os.ReadFile(u.Path)
		if err != nil {
			return "", fmt.Errorf("failed to read file: %w", err)
		}
		return string(body), nil

	case data:
		_, content, found := strings.Cut(u.Path, ",")
		if !found {
			return "", fmt.Errorf("invalid data URL: missing comma")
		}
		return content + "\n", nil
	}

	portStr := strconv.Itoa(u.Port)
	ck := net.JoinHostPort(u.Host, portStr)
	socketCache.mu.Lock()
	conn, ok := socketCache.conns[ck]
	socketCache.mu.Unlock()

	if !ok {
		newConn := new(net.Dialer)
		conn, err := newConn.DialContext(ctx, "tcp", net.JoinHostPort(u.Host, strconv.Itoa(u.Port)))
		if err != nil {
			return "", fmt.Errorf("failed to connect to the address on the named network: %q", err.Error())
		}

		if u.Scheme == https {
			tlsConn := tls.Client(conn, &tls.Config{ServerName: u.Host})
			if err := tlsConn.Handshake(); err != nil {
				return "", fmt.Errorf("TLS handshake failed: %w", err)
			}

			conn = tlsConn
		}

		socketCache.mu.Lock()
		socketCache.conns[ck] = conn
		socketCache.mu.Unlock()

	}
	newConn := new(net.Dialer)
	conn, err := newConn.DialContext(ctx, "tcp", net.JoinHostPort(u.Host, strconv.Itoa(u.Port)))
	if err != nil {
		return "", fmt.Errorf("failed to connect to the address on the named network: %q", err.Error())
	}

	defer conn.Close()
	if u.Scheme == https {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: u.Host})
		if err := tlsConn.Handshake(); err != nil {
			return "", fmt.Errorf("TLS handshake failed: %w", err)
		}

		conn = tlsConn
	}

	request := fmt.Sprintf(
		"GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\nUser-Agent: WebBrowserEngineering\r\n\r\n",
		u.Path, u.Host,
	)

	if _, err := conn.Write([]byte(request)); err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read status line: %w", err)
	}

	parts := strings.SplitN(strings.TrimRight(statusLine, "\r\n"), " ", 3)
	// returns ["HTTP/1.0", "200", "OK"]
	// version, status, explanation := parts[0], parts[1], parts[2]
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed status line: %q", statusLine)
	}

	responseHeaders := map[string]string{}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("failed to read headers: %w", err)
		}

		if line == "\r\n" {
			break
		}

		header, value, found := strings.Cut(line, ":")
		if !found {
			return "", fmt.Errorf("malformed header: %q", line)
		}
		responseHeaders[strings.ToLower(header)] = strings.TrimSpace(value)
	}
	if _, ok := responseHeaders["transfer-encoding"]; ok {
		return "", fmt.Errorf("transfer-encoding not supported")
	}
	if _, ok := responseHeaders["content-encoding"]; ok {
		return "", fmt.Errorf("content-encoding not supported")
	}

	contentLength, err := strconv.Atoi(responseHeaders["content-length"])
	if err != nil {
		return "", fmt.Errorf("missing or invalid content-length: %w", err)
	}

	content := make([]byte, contentLength)
	if _, err := io.ReadFull(reader, content); err != nil {
		return "", fmt.Errorf("failed to read body: %w", err)
	}

	return string(content), nil
}
