package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/ktr0731/evans/grpc/grpcreflection"
	"github.com/ktr0731/evans/logger"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// createInsecureTLSConfig creates a TLS configuration optimized for environments with self-signed certificates.
func createInsecureTLSConfig(cert, certKey string) (*tls.Config, error) {
	config := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "",
		
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return nil
		},
		VerifyConnection: func(cs tls.ConnectionState) error {
			return nil
		},
	}

	if cert != "" && certKey != "" {
		certificate, err := tls.LoadX509KeyPair(cert, certKey)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to load client certificate pair: cert=%s, key=%s", cert, certKey)
		}
		config.Certificates = []tls.Certificate{certificate}
		
		// Client certificate configuration for mutual TLS - set after certificates are loaded
		config.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			// Return the first available certificate when server requests one
			if len(config.Certificates) > 0 {
				return &config.Certificates[0], nil
			}
			return nil, nil
		}
		
		logger.Printf("Loaded client certificate for mutual TLS: %s", cert)
	} else if cert != "" || certKey != "" {
		return nil, ErrMutualAuthParamsAreNotEnough
	}

	return config, nil
}

// normalizeAddress converts localhost to IP address for better TLS compatibility
func normalizeAddress(addr string) string {
	if strings.Contains(addr, "localhost") {
		// Replace localhost with 127.0.0.1 to avoid hostname verification issues
		normalized := strings.ReplaceAll(addr, "localhost", "127.0.0.1")
		logger.Printf("DEBUG: Normalized address from %s to %s", addr, normalized)
		return normalized
	}
	return addr
}

// isLocalhostAddress checks if the address is a localhost/loopback address
func isLocalhostAddress(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// If we can't parse it, check the whole string
		host = addr
	}
	
	return host == "localhost" || 
		   host == "127.0.0.1" || 
		   host == "::1" || 
		   strings.HasPrefix(host, "127.") ||
		   host == ""
}

// RPC represents a RPC which belongs to a gRPC service.
type RPC struct {
	Name               string
	FullyQualifiedName string
	RequestType        *Type
	ResponseType       *Type
	IsServerStreaming  bool
	IsClientStreaming  bool
}

// Type is a type for representing requests/responses.
type Type struct {
	// Name is the name of Type.
	Name string

	// FullyQualifiedName is the name that contains the package name this Type belongs.
	FullyQualifiedName string

	// New instantiates a new instance of Type.  It is used for decode requests and responses.
	New func() interface{}
}

// Client represents the gRPC client.
type Client interface {
	// Invoke invokes a request req to the gRPC server. Then, Invoke decodes the response to res.
	Invoke(ctx context.Context, fqrn string, req, res interface{}) (header, trailer metadata.MD, _ error)

	// NewClientStream creates a new client stream.
	NewClientStream(ctx context.Context, streamDesc *grpc.StreamDesc, fqrn string) (ClientStream, error)

	// NewServerStream creates a new server stream.
	NewServerStream(ctx context.Context, streamDesc *grpc.StreamDesc, fqrn string) (ServerStream, error)

	// NewBidiStream creates a new bidirectional stream.
	NewBidiStream(ctx context.Context, streamDesc *grpc.StreamDesc, fqrn string) (BidiStream, error)

	// Close closes all connections the client has.
	Close(ctx context.Context) error

	// Header returns all request headers (metadata) Client has.
	Header() Headers

	grpcreflection.Client
}

type ClientStream interface {
	// Header returns the response header.
	Header() (metadata.MD, error)
	// Trailer returns the response trailer.
	Trailer() metadata.MD
	Send(req interface{}) error
	CloseAndReceive(res interface{}) error
}

type ServerStream interface {
	// Header returns the response header.
	Header() (metadata.MD, error)
	// Trailer returns the response trailer.
	Trailer() metadata.MD
	Send(req interface{}) error
	Receive(res interface{}) error
}

type BidiStream interface {
	// Header returns the response header.
	Header() (metadata.MD, error)
	// Trailer returns the response trailer.
	Trailer() metadata.MD
	Send(req interface{}) error
	Receive(res interface{}) error
	CloseSend() error
}

type client struct {
	conn    *grpc.ClientConn
	headers Headers

	grpcreflection.Client
}

var ErrMutualAuthParamsAreNotEnough = errors.New("cert and certkey are required to authenticate mutually")

// NewClient creates a new gRPC client with enhanced TLS support for self-signed certificates and localhost connections.
//
// Parameters:
//   - addr: Server address (e.g., "localhost:50001")
//   - serverName: Server name for TLS verification (ignored in insecure mode)
//   - useReflection: Enable gRPC reflection for dynamic service discovery
//   - useTLS: Enable TLS/SSL connection
//   - trustCA: Trust server certificates (ignored in insecure mode)
//   - cacert: CA certificate file (ignored in insecure mode)
//   - cert: Client certificate file for mutual TLS
//   - certKey: Client private key file for mutual TLS
//   - headers: Additional gRPC headers
func NewClient(addr, serverName string, useReflection, useTLS bool, trustCA bool, cacert, cert, certKey string, headers map[string][]string) (Client, error) {
    var opts []grpc.DialOption

    if !useTLS {
        opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
    } else {
        // 1) Convert any hostname (including 'localhost') to IP -> suppresses SNI.
        addr = forceIP(addr)

        // 2) Build insecure (no verification) TLS config + optional client cert.
        tlsConfig, err := createInsecureTLSConfig(cert, certKey)
        if err != nil {
            return nil, errors.Wrap(err, "failed to create TLS configuration")
        }

        // 3) Do NOT set ServerName if we want no SNI.
        // Only set if caller explicitly wants SNI and original addr stayed a hostname.
        if serverName != "" && net.ParseIP(serverName) == nil {
            tlsConfig.ServerName = serverName
        }

        creds := credentials.NewTLS(tlsConfig)
        opts = append(opts, grpc.WithTransportCredentials(creds))
    }

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    conn, err := grpc.DialContext(ctx, addr, opts...)
    if err != nil {
        return nil, errors.Wrapf(err, "failed to dial gRPC server at %s", addr)
    }

    c := &client{conn: conn, headers: Headers{}}
    if useReflection {
        c.Client = grpcreflection.NewClient(conn, headers)
    }
    return c, nil
}

func (c *client) Invoke(ctx context.Context, fqrn string, req, res interface{}) (header, trailer metadata.MD, _ error) {
	logger.Scriptln(func() []interface{} {
		md, ok := metadata.FromOutgoingContext(ctx)
		if !ok {
			return nil
		}
		return []interface{}{md}
	})

	endpoint, err := fqrnToEndpoint(fqrn)
	if err != nil {
		return nil, nil, err
	}
	loggingRequest(req)
	wakeUpClientConn(c.conn)
	opts := []grpc.CallOption{grpc.Header(&header), grpc.Trailer(&trailer)}
	err = c.conn.Invoke(ctx, endpoint, req, res, opts...)
	return header, trailer, err
}

func (c *client) Close(ctx context.Context) error {
	doneCh := make(chan error)
	go func() {
		var result error
		if c.Client != nil {
			c.Client.Reset()
		}
		if err := c.conn.Close(); err != nil {
			result = multierror.Append(result, errors.Wrap(err, "failed to close gRPC client"))
		}
		doneCh <- result
	}()

	select {
	case <-ctx.Done():
		return nil
	case err := <-doneCh:
		return err
	}
}

func (c *client) Header() Headers {
	return c.headers
}

type clientStream struct {
	cs grpc.ClientStream
}

func (s *clientStream) Header() (metadata.MD, error) {
	return s.cs.Header()
}

func (s *clientStream) Trailer() metadata.MD {
	return s.cs.Trailer()
}

func (s *clientStream) Send(req interface{}) error {
	loggingRequest(req)
	return s.cs.SendMsg(req)
}

func (s *clientStream) CloseAndReceive(res interface{}) error {
	if err := s.cs.CloseSend(); err != nil {
		return errors.Wrap(err, "failed to close client stream")
	}

	err := s.cs.RecvMsg(res)
	if err != nil && err != io.EOF {
		return errors.Wrap(err, "failed to close and receive response")
	}
	return nil
}

func (c *client) NewClientStream(ctx context.Context, streamDesc *grpc.StreamDesc, fqrn string) (ClientStream, error) {
	endpoint, err := fqrnToEndpoint(fqrn)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert fqrn to endpoint")
	}
	wakeUpClientConn(c.conn)
	cs, err := c.conn.NewStream(ctx, streamDesc, endpoint)
	if err != nil {
		return nil, errors.Wrap(err, "failed to instantiate gRPC stream")
	}
	return &clientStream{cs}, nil
}

type serverStream struct {
	*clientStream
}

func (s *serverStream) Receive(res interface{}) error {
	return s.cs.RecvMsg(res)
}

func (c *client) NewServerStream(ctx context.Context, streamDesc *grpc.StreamDesc, fqrn string) (ServerStream, error) {
	s, err := c.NewClientStream(ctx, streamDesc, fqrn)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create server stream")
	}
	return &serverStream{s.(*clientStream)}, nil
}

type bidiStream struct {
	s *serverStream
}

func (s *bidiStream) Header() (metadata.MD, error) {
	return s.s.Header()
}

func (s *bidiStream) Trailer() metadata.MD {
	return s.s.Trailer()
}

func (s *bidiStream) Send(req interface{}) error {
	loggingRequest(req)
	return s.s.cs.SendMsg(req)
}

func (s *bidiStream) Receive(res interface{}) error {
	return s.s.cs.RecvMsg(res)
}

func (s *bidiStream) CloseSend() error {
	return s.s.cs.CloseSend()
}

func (c *client) NewBidiStream(ctx context.Context, streamDesc *grpc.StreamDesc, fqrn string) (BidiStream, error) {
	s, err := c.NewServerStream(ctx, streamDesc, fqrn)
	if err != nil {
		return nil, err
	}
	return &bidiStream{s.(*serverStream)}, nil
}

// fqrnToEndpoint converts FullQualifiedRPCName to endpoint
//
// e.g.
//
//	pkg_name.svc_name.rpc_name -> /pkg_name.svc_name/rpc_name
func fqrnToEndpoint(fqrn string) (string, error) {
	sp := strings.Split(fqrn, ".")
	// FQRN should contain at least service and rpc name.
	if len(sp) < 2 {
		return "", errors.New("invalid FQRN format")
	}

	return fmt.Sprintf("/%s/%s", strings.Join(sp[:len(sp)-1], "."), sp[len(sp)-1]), nil
}

func wakeUpClientConn(conn *grpc.ClientConn) {
	if conn.GetState() == connectivity.TransientFailure {
		conn.ResetConnectBackoff()
	}
}

func loggingRequest(req interface{}) {
	logger.Scriptln(func() []interface{} {
		b, err := json.MarshalIndent(&req, "", "  ")
		if err != nil {
			return nil
		}
		return []interface{}{"request:\n" + string(b)}
	})
}

// forceIP converts addr's host to a numeric IP (IPv4 preferred) so gRPC will NOT send SNI.
// gRPC only injects SNI when the host is a hostname (not an IP). Using an IP removes
// "No match found for server name: <host>" server
func forceIP(addr string) string {
    host, port, err := net.SplitHostPort(addr)
    if err != nil {
        return addr
    }
    if net.ParseIP(host) != nil {
        return addr
    }
    ips, err := net.LookupIP(host)
    if err != nil || len(ips) == 0 {
        return addr
    }
    // Prefer IPv4
    for _, ip := range ips {
        if v4 := ip.To4(); v4 != nil {
            return net.JoinHostPort(v4.String(), port)
        }
    }
    return net.JoinHostPort(ips[0].String(), port)
}
