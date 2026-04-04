package nbi3

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bokwoon95/nbi3/sq"
	"github.com/bokwoon95/nbi3/stacktrace"
	"github.com/caddyserver/certmagic"
	"github.com/klauspost/cpuid/v2"
	"golang.org/x/crypto/blake2b"
)

func (nbrew *Notebrew) NewServer() (*http.Server, error) {
	server := &http.Server{
		ErrorLog: log.New(&LogFilter{Stderr: os.Stderr}, "", log.LstdFlags),
		Handler:  nbrew,
	}
	var onEvent func(ctx context.Context, event string, data map[string]any) error
	if nbrew.MonitoringConfig.Email != "" && nbrew.Mailer != nil {
		onEvent = func(ctx context.Context, event string, data map[string]any) error {
			if event == "tls_get_certificate" {
				return nil
			}
			data["certmagic.event"] = event
			b, err := json.Marshal(data)
			if err != nil {
				fmt.Println(err)
				return nil
			}
			fmt.Println(string(b))
			if event != "cert_failed" {
				return nil
			}
			renewal := fmt.Sprint(data["renewal"])
			identifier := fmt.Sprint(data["identifier"])
			remaining := fmt.Sprint(data["remaining"])
			issuers := fmt.Sprint(data["issuers"])
			errmsg := fmt.Sprint(data["error"])
			nbrew.BackgroundWaitGroup.Add(1)
			go func() {
				defer func() {
					if v := recover(); v != nil {
						fmt.Println(stacktrace.New(fmt.Errorf("panic: %v", v)))
					}
				}()
				defer nbrew.BackgroundWaitGroup.Done()
				mail := Mail{
					MailFrom: nbrew.MailFrom,
					RcptTo:   nbrew.MonitoringConfig.Email,
					Headers: []string{
						"Subject", "notebrew: certificate renewal for " + identifier + " failed: " + errmsg,
						"Content-Type", "text/plain; charset=utf-8",
					},
					Body: strings.NewReader("Certificate renewal failed." +
						"\r\nRenewal: " + renewal +
						"\r\nThe name on the certificate: " + identifier +
						"\r\nThe issuer(s) tried: " + issuers +
						"\r\nTime left on the certificate: " + remaining +
						"\r\nError: " + errmsg,
					),
				}
				select {
				case <-ctx.Done():
				case <-nbrew.BackgroundContext.Done():
				case nbrew.Mailer.C <- mail:
				}
			}()
			return nil
		}
	}
	switch nbrew.Port {
	case 443:
		server.Addr = ":443"
		server.ReadHeaderTimeout = 5 * time.Minute
		server.WriteTimeout = 60 * time.Minute
		server.IdleTimeout = 5 * time.Minute
		// staticCertConfig is the certmagic config responsible for managing
		// statically-known domains in the nbrew.ManagingDomains slice.
		var staticCertConfig *certmagic.Config
		staticCertCache := certmagic.NewCache(certmagic.CacheOptions{
			GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
				return staticCertConfig, nil
			},
			Logger: nbrew.CertLogger,
		})
		staticCertConfig = certmagic.New(staticCertCache, certmagic.Config{})
		staticCertConfig.OnEvent = onEvent
		staticCertConfig.Storage = nbrew.CertStorage
		staticCertConfig.Logger = nbrew.CertLogger
		if nbrew.DNSProvider != nil {
			staticCertConfig.Issuers = []certmagic.Issuer{
				certmagic.NewACMEIssuer(staticCertConfig, certmagic.ACMEIssuer{
					CA:        certmagic.DefaultACME.CA,
					TestCA:    certmagic.DefaultACME.TestCA,
					Logger:    nbrew.CertLogger,
					HTTPProxy: certmagic.DefaultACME.HTTPProxy,
					DNS01Solver: &certmagic.DNS01Solver{
						DNSManager: certmagic.DNSManager{
							DNSProvider: nbrew.DNSProvider,
							Logger:      nbrew.CertLogger,
						},
					},
				}),
			}
		} else {
			staticCertConfig.Issuers = []certmagic.Issuer{
				certmagic.NewACMEIssuer(staticCertConfig, certmagic.ACMEIssuer{
					CA:        certmagic.DefaultACME.CA,
					TestCA:    certmagic.DefaultACME.TestCA,
					Logger:    nbrew.CertLogger,
					HTTPProxy: certmagic.DefaultACME.HTTPProxy,
				}),
			}
		}
		if len(nbrew.ManagingDomains) == 0 {
			fmt.Printf("WARNING: notebrew is listening on port 443 but no domains are pointing at this current machine's IP address (%s/%s). It means no traffic can reach this current machine. Please configure your DNS correctly.\n", nbrew.InboundIP4.String(), nbrew.InboundIP6.String())
		}
		err := staticCertConfig.ManageSync(context.Background(), nbrew.ManagingDomains)
		if err != nil {
			return nil, err
		}
		// dynamicCertConfig is the certmagic config responsible for managing
		// dynamically-determined domains present in the site table.
		var dynamicCertConfig *certmagic.Config
		dynamicCertCache := certmagic.NewCache(certmagic.CacheOptions{
			GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
				return dynamicCertConfig, nil
			},
			Logger: nbrew.CertLogger,
		})
		dynamicCertConfig = certmagic.New(dynamicCertCache, certmagic.Config{})
		dynamicCertConfig.OnEvent = onEvent
		dynamicCertConfig.Storage = nbrew.CertStorage
		dynamicCertConfig.Logger = nbrew.CertLogger
		dynamicCertConfig.OnDemand = &certmagic.OnDemandConfig{
			DecisionFunc: func(ctx context.Context, name string) error {
				var siteName string
				if certmagic.MatchWildcard(name, "*."+nbrew.ContentDomain) {
					siteName = strings.TrimSuffix(name, "."+nbrew.ContentDomain)
				} else {
					siteName = name
				}
				exists, err := sq.FetchExists(ctx, nbrew.DB, sq.Query{
					Dialect: nbrew.Dialect,
					Format:  "SELECT 1 FROM site WHERE site_name = {}",
					Values:  []any{siteName},
				})
				if err != nil {
					return err
				}
				if !exists {
					return fmt.Errorf("site does not exist")
				}
				return nil
			},
		}
		// TLSConfig logic copied from (*certmagic.Config).TLSConfig(). The
		// only modification is that in GetCertificate we obtain the
		// certificate from either staticCertConfig or dynamicCertConfig based
		// on clientHello.
		server.TLSConfig = &tls.Config{
			NextProtos: []string{"h2", "http/1.1", "acme-tls/1"},
			GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if clientHello.ServerName == "" {
					return nil, fmt.Errorf("server name required")
				}
				for _, domain := range nbrew.ManagingDomains {
					if certmagic.MatchWildcard(clientHello.ServerName, domain) {
						certificate, err := staticCertConfig.GetCertificate(clientHello)
						if err != nil {
							return nil, err
						}
						return certificate, nil
					}
				}
				certificate, err := dynamicCertConfig.GetCertificate(clientHello)
				if err != nil {
					return nil, err
				}
				return certificate, nil
			},
			MinVersion: tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
			},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			PreferServerCipherSuites: true,
		}
		if cpuid.CPU.Supports(cpuid.AESNI) {
			server.TLSConfig.CipherSuites = []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			}
		}
	case 80:
		server.Addr = ":80"
	default:
		if len(nbrew.ProxyConfig.RealIPHeaders) == 0 && len(nbrew.ProxyConfig.ProxyIPs) == 0 && nbrew.CMSDomain != "0.0.0.0" {
			server.Addr = "localhost:" + strconv.Itoa(nbrew.Port)
		} else {
			server.Addr = ":" + strconv.Itoa(nbrew.Port)
		}
	}
	return server, nil
}

type LogFilter struct {
	Stderr io.Writer
}

func (logFilter *LogFilter) Write(p []byte) (n int, err error) {
	if bytes.Contains(p, []byte("http: TLS handshake error from ")) ||
		bytes.Contains(p, []byte("http2: RECEIVED GOAWAY")) ||
		bytes.Contains(p, []byte("http2: server: error reading preface from client")) {
		return 0, nil
	}
	return logFilter.Stderr.Write(p)
}

func (nbrew *Notebrew) RedirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "HEAD" {
		http.Error(w, "Use HTTPS", http.StatusBadRequest)
		return
	}
	// Redirect HTTP to HTTPS only if it isn't an API call.
	// https://jviide.iki.fi/http-redirects
	r.ParseForm()
	if r.Host != nbrew.CMSDomain || !r.Form.Has("api") {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		} else {
			host = net.JoinHostPort(host, "443")
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusFound)
		return
	}
	// If someone does make an api call via HTTP, revoke their
	// session token.
	var sessionTokenHashes [][]byte
	header := r.Header.Get("Authorization")
	if header != "" {
		sessionToken, err := hex.DecodeString(fmt.Sprintf("%048s", strings.TrimPrefix(header, "Bearer ")))
		if err == nil && len(sessionToken) == 24 {
			var sessionTokenHash [8 + blake2b.Size256]byte
			checksum := blake2b.Sum256(sessionToken[8:])
			copy(sessionTokenHash[:8], sessionToken[:8])
			copy(sessionTokenHash[8:], checksum[:])
			sessionTokenHashes = append(sessionTokenHashes, sessionTokenHash[:])
		}
	}
	cookie, _ := r.Cookie("session")
	if cookie != nil && cookie.Value != "" {
		sessionToken, err := hex.DecodeString(fmt.Sprintf("%048s", cookie.Value))
		if err == nil && len(sessionToken) == 24 {
			var sessionTokenHash [8 + blake2b.Size256]byte
			checksum := blake2b.Sum256(sessionToken[8:])
			copy(sessionTokenHash[:8], sessionToken[:8])
			copy(sessionTokenHash[8:], checksum[:])
			sessionTokenHashes = append(sessionTokenHashes, sessionTokenHash[:])
		}
	}
	if len(sessionTokenHashes) > 0 {
		_, _ = sq.Exec(r.Context(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "DELETE FROM session WHERE session_token_hash IN ({sessionTokenHashes})",
			Values: []any{
				sq.Param("sessionTokenHashes", sessionTokenHashes),
			},
		})
	}
	http.Error(w, "Use HTTPS", http.StatusBadRequest)
}
