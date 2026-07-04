package network

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
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

const defaultKeepAlive = 5 * time.Second

type URL struct {
	Scheme     Scheme
	Host       string
	Port       int
	Path       string
	ViewSource bool
}

var socketCache = struct {
	mu    sync.Mutex
	conns map[string]struct {
		conn   net.Conn
		reader *bufio.Reader
		expiry time.Time
	}
}{conns: make(map[string]struct {
	conn   net.Conn
	reader *bufio.Reader
	expiry time.Time
})}

type responseCacheEntry struct {
	body   string
	expiry time.Time
}

var responseCache = struct {
	mu      sync.Mutex
	entries map[string]responseCacheEntry
}{entries: make(map[string]responseCacheEntry)}

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

	if Scheme(scheme) == file {
		u.Scheme = file
		u.Path = "/" + rest
		return u, nil
	}

	if !strings.Contains(rest, "/") {
		rest += "/"
	}

	slashIdx := strings.Index(rest, "/")
	host := rest[:slashIdx]
	path := rest[slashIdx:]

	port := 0
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

func readChunked(r *bufio.Reader) ([]byte, error) {
	var body []byte

	for {
		sizeLine, err := r.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("failed to read chunk size: %w", err)
		}

		sizeField := strings.TrimSpace(strings.SplitN(sizeLine, ";", 2)[0])
		size, err := strconv.ParseInt(sizeField, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid chunk size %q: %w", sizeField, err)
		}

		if size == 0 {
			for {
				trailer, err := r.ReadString('\n')
				if err != nil {
					return nil, fmt.Errorf("failed to read trailer: %w", err)
				}
				if trailer == "\r\n" || trailer == "\n" {
					break
				}
			}
			break
		}

		chunk := make([]byte, size)
		if _, err := io.ReadFull(r, chunk); err != nil {
			return nil, fmt.Errorf("failed to read chunk body: %w", err)
		}

		body = append(body, chunk...)

		if _, err := r.Discard(2); err != nil {
			return nil, fmt.Errorf("failed to read chunk terminator: %w", err)
		}
	}

	return body, nil
}

func socketLifetime(headers map[string]string) time.Time {
	if ka := headers["keep-alive"]; strings.Contains(ka, "timeout=") {
		field := strings.Split(ka, "timeout=")[1]
		if secs, err := strconv.Atoi(strings.Split(field, ",")[0]); err == nil {
			return time.Now().Add(time.Duration(secs) * time.Second)
		}
	}
	return time.Now().Add(defaultKeepAlive)
}

func isPersistentHTTP(version string, headers map[string]string) bool {
	connection := strings.ToLower(strings.TrimSpace(headers["connection"]))

	switch version {
	case "HTTP/1.1":
		return connection != "close"
	case "HTTP/1.0":
		return connection == "keep-alive"
	default:
		return false
	}
}

func (u *URL) Request(ctx context.Context, maxRedirects int) (string, error) {
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
		return content, nil
	}

	respKey := fmt.Sprintf("%s://%s:%d%s", u.Scheme, u.Host, u.Port, u.Path)

	responseCache.mu.Lock()
	if entry, ok := responseCache.entries[respKey]; ok {
		if time.Now().Before(entry.expiry) {
			responseCache.mu.Unlock()
			return entry.body, nil
		}
		delete(responseCache.entries, respKey)
	}
	responseCache.mu.Unlock()

	portStr := strconv.Itoa(u.Port)
	ck := net.JoinHostPort(u.Host, portStr)

	socketCache.mu.Lock()
	cached, ok := socketCache.conns[ck]
	socketCache.mu.Unlock()

	var conn net.Conn
	var reader *bufio.Reader

	if ok {
		if cached.expiry.IsZero() || time.Now().After(cached.expiry) {
			socketCache.mu.Lock()
			delete(socketCache.conns, ck)
			socketCache.mu.Unlock()
			cached.conn.Close()
			ok = false
		} else {
			conn = cached.conn
			reader = cached.reader
		}
	}

	if !ok {
		var err error
		dialer := new(net.Dialer)
		conn, err = dialer.DialContext(ctx, "tcp", ck)
		if err != nil {
			return "", fmt.Errorf("failed to connect to network: %w", err)
		}

		if u.Scheme == https {
			tlsConn := tls.Client(conn, &tls.Config{ServerName: u.Host})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return "", fmt.Errorf("TLS handshake failed: %w", err)
			}
			conn = tlsConn
		}

		reader = bufio.NewReader(conn)
	}

	request := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: WebBrowserEngineering\r\nAccept-Encoding: gzip\r\n\r\n",
		u.Path, u.Host,
	)

	if _, err := conn.Write([]byte(request)); err != nil {
		conn.Close()
		return "", fmt.Errorf("failed to send request: %w", err)
	}

	statusLine, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return "", fmt.Errorf("failed to read status line: %w", err)
	}

	parts := strings.SplitN(strings.TrimRight(statusLine, "\r\n"), " ", 3)
	if len(parts) != 3 {
		conn.Close()
		return "", fmt.Errorf("malformed status line: %q", statusLine)
	}

	version := parts[0]
	status := parts[1]

	responseHeaders := map[string]string{}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			conn.Close()
			return "", fmt.Errorf("failed to read headers: %w", err)
		}
		if line == "\r\n" {
			break
		}

		header, value, found := strings.Cut(line, ":")
		if !found {
			conn.Close()
			return "", fmt.Errorf("malformed header: %q", line)
		}

		responseHeaders[strings.ToLower(strings.TrimSpace(header))] = strings.TrimSpace(value)
	}

	if strings.HasPrefix(status, "3") {
		if maxRedirects == 0 {
			conn.Close()
			return "", fmt.Errorf("too many redirects")
		}

		location := responseHeaders["location"]
		if strings.HasPrefix(location, "/") {
			location = fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, location)
		}

		redirectURL, err := NewURL(location)
		if err != nil {
			conn.Close()
			return "", fmt.Errorf("invalid redirect location: %w", err)
		}

		return redirectURL.Request(ctx, maxRedirects-1)
	}

	te := responseHeaders["transfer-encoding"]
	if te != "" && te != "chunked" {
		conn.Close()
		return "", fmt.Errorf("unsupported transfer-encoding: %s", te)
	}

	ce := responseHeaders["content-encoding"]
	if ce != "" && ce != "gzip" {
		conn.Close()
		return "", fmt.Errorf("unsupported content-encoding: %s", ce)
	}

	var content []byte
	canReuseSocket := true

	if te == "chunked" {
		content, err = readChunked(reader)
		if err != nil {
			conn.Close()
			return "", err
		}
	} else if clStr, hasCL := responseHeaders["content-length"]; hasCL {
		contentLength, err := strconv.Atoi(clStr)
		if err != nil {
			conn.Close()
			return "", fmt.Errorf("invalid content-length: %w", err)
		}

		content = make([]byte, contentLength)
		if _, err := io.ReadFull(reader, content); err != nil {
			conn.Close()
			return "", fmt.Errorf("failed to read body: %w", err)
		}
	} else {
		content, err = io.ReadAll(reader)
		if err != nil && err != io.EOF {
			conn.Close()
			return "", fmt.Errorf("failed to read until EOF: %w", err)
		}
		canReuseSocket = false
	}

	if ce == "gzip" {
		gz, err := gzip.NewReader(bytes.NewReader(content))
		if err != nil {
			conn.Close()
			return "", fmt.Errorf("failed to init gzip reader: %w", err)
		}

		content, err = io.ReadAll(gz)
		gz.Close()
		if err != nil {
			conn.Close()
			return "", fmt.Errorf("failed to decompress body: %w", err)
		}
	}

	if canReuseSocket && isPersistentHTTP(version, responseHeaders) {
		socketExpiry := socketLifetime(responseHeaders)
		socketCache.mu.Lock()
		socketCache.conns[ck] = struct {
			conn   net.Conn
			reader *bufio.Reader
			expiry time.Time
		}{
			conn:   conn,
			reader: reader,
			expiry: socketExpiry,
		}
		socketCache.mu.Unlock()
	} else {
		conn.Close()
	}

	result := strings.ToValidUTF8(string(content), "\uFFFD")

	cacheExpiry := time.Time{}
	cacheControl := responseHeaders["cache-control"]
	if strings.Contains(cacheControl, "max-age=") {
		cacheParts := strings.Split(cacheControl, "max-age=")
		if len(cacheParts) > 1 {
			maxAgeStr := strings.Split(cacheParts[1], ",")[0]
			if maxAge, err := strconv.Atoi(strings.TrimSpace(maxAgeStr)); err == nil {
				cacheExpiry = time.Now().Add(time.Duration(maxAge) * time.Second)
			}
		}
	}

	if status == "200" && !cacheExpiry.IsZero() && !strings.Contains(cacheControl, "no-store") {
		responseCache.mu.Lock()
		responseCache.entries[respKey] = responseCacheEntry{
			body:   result,
			expiry: cacheExpiry,
		}
		responseCache.mu.Unlock()
	}

	return result, nil
}
