package turn

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing/common/metadata"
	httpproxy "github.com/sagernet/sing/protocol/http"
	"golang.org/x/net/proxy"
)

// NewDialer validates the explicit route before a paid profile starts.
func NewDialer(proxyURL string) (func(context.Context, string, string) (net.Conn, error), error) {
	direct := &net.Dialer{Timeout: 30 * time.Second}
	if proxyURL == "" {
		return direct.DialContext, nil
	}
	invalid := errors.New("nullgate: target proxy must be an absolute SOCKS5 or HTTP(S) URL without path, query, or fragment")
	u, err := url.Parse(proxyURL)
	if err != nil || u.Hostname() == "" || u.Opaque != "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		strings.ContainsAny(u.Hostname(), "\r\n\t /?#@") {
		return nil, invalid
	}
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		case "socks5", "socks5h":
			port = "1080"
		default:
			return nil, invalid
		}
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 || strings.HasSuffix(u.Host, ":") {
		return nil, invalid
	}
	address := net.JoinHostPort(u.Hostname(), port)
	var username, password string
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
	}
	switch u.Scheme {
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if u.User != nil {
			if len(username) > 255 || len(password) > 255 {
				return nil, invalid
			}
			auth = &proxy.Auth{User: username, Password: password}
		}
		dialer, err := proxy.SOCKS5("tcp", address, auth, direct)
		if err != nil {
			return nil, invalid
		}
		contextDialer, ok := dialer.(proxy.ContextDialer)
		if !ok {
			return nil, errors.New("nullgate: SOCKS5 provider does not support cancellation")
		}
		return contextDialer.DialContext, nil
	case "http", "https":
		var tlsConfig *tls.Config
		if u.Scheme == "https" {
			tlsConfig = &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}
		}
		dialer := httpproxy.NewClient(httpproxy.Options{
			Dialer: &proxyDialer{dialer: direct, tls: tlsConfig},
			Server: metadata.ParseSocksaddr(address), Username: username, Password: password,
		})
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, metadata.ParseSocksaddr(address))
		}, nil
	default:
		return nil, invalid
	}
}

// The maintained CONNECT provider owns the handshake; this supplies its stream.
type proxyDialer struct {
	dialer *net.Dialer
	tls    *tls.Config
}

func (d *proxyDialer) DialContext(ctx context.Context, network string, destination metadata.Socksaddr) (net.Conn, error) {
	if network != "tcp" {
		return nil, errors.New("nullgate: target route supports TCP only")
	}
	stream, err := d.dialer.DialContext(ctx, network, destination.String())
	if err != nil || d.tls == nil {
		return stream, err
	}
	secure := tls.Client(stream, d.tls)
	if err := secure.HandshakeContext(ctx); err != nil {
		stream.Close()
		return nil, err
	}
	return secure, nil
}

func (*proxyDialer) ListenPacket(context.Context, metadata.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("nullgate: target route does not open UDP sockets")
}
