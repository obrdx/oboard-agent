package netdiag

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

// LocalAddresses returns the addresses assigned to this host's interfaces.
type LocalAddresses func() ([]netip.Addr, error)

// InterfaceAddresses is the production LocalAddresses.
func InterfaceAddresses() ([]netip.Addr, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		if prefix, err := netip.ParsePrefix(addr.String()); err == nil {
			out = append(out, prefix.Addr().Unmap())
		}
	}
	return out, nil
}

// ValidateLANRequest re-checks the signed payload independently of
// Controller. The address must be a private LAN address that is not one of
// this host's own addresses, so a plugin can never reach services the node
// itself listens on through its private IP.
func ValidateLANRequest(p model.LANRequestTaskPayload, local LocalAddresses) (netip.Addr, error) {
	ip, err := netip.ParseAddr(p.Address)
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, invalid("address must be an IP literal")
	}
	ip = ip.Unmap()
	if !model.LANAddressAllowed(ip) {
		return netip.Addr{}, fail(model.NetworkDiagnosticCodeTargetNotAllowed, ip.String()+" is not a private LAN address (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7)")
	}
	if local != nil {
		addrs, err := local()
		if err != nil {
			return netip.Addr{}, fail(model.NetworkDiagnosticCodeFailed, "cannot list local interface addresses")
		}
		for _, own := range addrs {
			if own == ip {
				return netip.Addr{}, fail(model.NetworkDiagnosticCodeTargetNotAllowed, ip.String()+" is an address of this server")
			}
		}
	}
	switch {
	case p.TargetID == "" || len(p.TargetID) > 64:
		return netip.Addr{}, invalid("target_id is invalid")
	case p.Scheme != model.LANRequestSchemeHTTP && p.Scheme != model.LANRequestSchemeHTTPS:
		return netip.Addr{}, invalid("scheme must be http or https")
	case p.InsecureTLS && p.Scheme != model.LANRequestSchemeHTTPS:
		return netip.Addr{}, invalid("insecure_tls is only valid for https")
	case p.Port < 1 || p.Port > 65535:
		return netip.Addr{}, invalid("port is out of range")
	case !model.LANRequestMethods[p.Method]:
		return netip.Addr{}, invalid("method is not supported")
	case p.TimeoutMS < 500 || p.TimeoutMS > model.LANRequestMaxTimeoutMS:
		return netip.Addr{}, invalid("timeout_ms is out of range")
	case p.MaxResponseBytes < 0 || p.MaxResponseBytes > model.LANRequestMaxResponseBytes:
		return netip.Addr{}, invalid("max_response_bytes is out of range")
	case len(p.Headers) > model.LANRequestMaxHeaders:
		return netip.Addr{}, invalid("too many headers")
	case len(p.PathPrefix) > model.LANRequestMaxPathPrefixBytes || !strings.HasPrefix(p.PathPrefix, "/"):
		return netip.Addr{}, invalid("path_prefix is invalid")
	}
	if err := validateLANPath(p.Path); err != nil {
		return netip.Addr{}, err
	}
	if !model.LANPathWithinPrefix(p.Path, p.PathPrefix) {
		return netip.Addr{}, fail(model.NetworkDiagnosticCodeTargetNotAllowed, "path "+p.Path+" is outside the declared prefix "+p.PathPrefix)
	}
	for name, value := range p.Headers {
		if !validHeaderName(name) || model.LANForbiddenRequestHeader(name) || len(value) > model.LANRequestMaxHeaderValueBytes || strings.ContainsAny(value, "\r\n\x00") {
			return netip.Addr{}, invalid("header " + name + " is not allowed")
		}
	}
	if base64.StdEncoding.DecodedLen(len(p.BodyBase64)) > model.LANRequestMaxBodyBytes+3 {
		return netip.Addr{}, invalid("body is too large")
	}
	return ip, nil
}

func validateLANPath(path string) error {
	if path == "" || len(path) > model.LANRequestMaxPathBytes || path[0] != '/' || strings.ContainsAny(path, "#\r\n\t \\") {
		return invalid("path must start with / and contain no fragment, whitespace or backslash")
	}
	rawPath, _, _ := strings.Cut(path, "?")
	decoded, err := url.PathUnescape(rawPath)
	if err != nil {
		return invalid("path is not valid percent-encoding")
	}
	for _, segment := range strings.Split(decoded, "/") {
		if segment == ".." || segment == "." {
			return invalid("path must not contain . or .. segments")
		}
	}
	return nil
}

func validHeaderName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
			return false
		}
	}
	return true
}

// LANRequest performs exactly one HTTP exchange with the granted LAN target.
// It never follows redirects, never uses environment proxies, dials only the
// validated literal address and returns at most MaxResponseBytes of body. A
// refused or timed-out connection is a result, not a task failure.
func LANRequest(ctx context.Context, dialer Dialer, local LocalAddresses, p model.LANRequestTaskPayload) (model.LANRequestResult, error) {
	result := model.LANRequestResult{OperationID: p.OperationID, TargetID: p.TargetID}
	ip, err := ValidateLANRequest(p, local)
	if err != nil {
		return result, err
	}
	body, err := base64.StdEncoding.DecodeString(p.BodyBase64)
	if err != nil || len(body) > model.LANRequestMaxBodyBytes {
		return result, invalid("body is not valid base64 or is too large")
	}
	limit := p.MaxResponseBytes
	if limit == 0 {
		limit = model.LANRequestDefaultResponseBytes
	}
	address := net.JoinHostPort(ip.String(), strconv.Itoa(p.Port))
	requestCtx, cancel := context.WithTimeout(ctx, time.Duration(p.TimeoutMS)*time.Millisecond)
	defer cancel()
	transport := &http.Transport{
		Proxy:               nil,
		DisableKeepAlives:   true,
		DisableCompression:  true,
		TLSHandshakeTimeout: time.Duration(p.TimeoutMS) * time.Millisecond,
		// #nosec G402 -- insecure_tls is declared per LAN target in the plugin manifest, shown in the administrator's permission review and limited to one granted private address.
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: p.InsecureTLS},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", address)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	target := p.Scheme + "://" + address + p.Path
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(requestCtx, p.Method, target, reader)
	if err != nil {
		return result, invalid("request is invalid")
	}
	request.Header.Set("User-Agent", "OBoard-Plugin/1")
	for name, value := range p.Headers {
		request.Header.Set(name, value)
	}
	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		result.ErrorClass = errorClass(err)
		result.DurationMS = sinceMS(started)
		return result, nil
	}
	defer response.Body.Close()
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	result.DurationMS = sinceMS(started)
	result.StatusCode = response.StatusCode
	if len(payload) > limit {
		payload, result.Truncated = payload[:limit], true
	}
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		result.Truncated = true
	}
	result.BodyBytes = len(payload)
	if len(payload) > 0 {
		result.BodyBase64 = base64.StdEncoding.EncodeToString(payload)
	}
	result.Headers = responseHeaders(response.Header)
	return result, nil
}

func responseHeaders(header http.Header) map[string]string {
	names := make([]string, 0, len(header))
	for name := range header {
		if strings.EqualFold(name, "Set-Cookie") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	out := map[string]string{}
	for _, name := range names {
		if len(out) >= model.LANRequestMaxResponseHeaders {
			break
		}
		value := strings.Join(header.Values(name), ", ")
		if len(value) > model.LANRequestMaxHeaderValueBytes {
			value = value[:model.LANRequestMaxHeaderValueBytes]
		}
		out[strings.ToLower(name)] = value
	}
	return out
}
