package domain

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

// Issuer obtains and caches Let's Encrypt certificates for the domain
// package. It is used in external mode, where the machine's webserver proxies
// /.well-known/acme-challenge/ to a loopback listener owned here. Built-in
// mode uses autocert.Manager instead.
type Issuer struct {
	mu      sync.Mutex
	dir     string
	port    int
	started bool
	client  *acme.Client
	tokens  map[string]string
	ln      net.Listener
	srv     *http.Server
}

func newIssuer(dir string, port int) *Issuer {
	return &Issuer{dir: dir, port: port, tokens: map[string]string{}}
}

// start loads the account key and brings up the loopback challenge handler.
// It is idempotent and only ever called when a certificate is actually
// needed, so a server that is not using domains makes no ACME network call
// and binds no extra port.
func (iss *Issuer) start() {
	iss.mu.Lock()
	if iss.started {
		iss.mu.Unlock()
		return
	}
	iss.started = true
	iss.mu.Unlock()
	if err := os.MkdirAll(iss.dir, 0700); err != nil {
		log.Printf("[domain] cert dir: %v", err)
	}

	key, err := iss.accountKey()
	if err != nil {
		log.Printf("[domain] ACME account key: %v", err)
	}

	iss.client = &acme.Client{Key: key, DirectoryURL: acme.LetsEncryptURL}
	iss.mu.Lock()
	iss.tokens = map[string]string{}
	iss.mu.Unlock()

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", iss.port))
	if err != nil {
		log.Printf("[domain] ACME challenge listener on :%d: %v", iss.port, err)
		return
	}
	iss.ln = ln
	iss.srv = &http.Server{Handler: iss}
	go func() {
		if err := iss.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("[domain] ACME challenge server stopped: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := iss.client.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil {
		// A pre-existing account for this key is the common, fine path.
		log.Printf("[domain] ACME account: %v", err)
	} else {
		log.Printf("[domain] ACME account registered, challenge listener on 127.0.0.1:%d", iss.port)
	}
}

// ServeHTTP answers http-01 challenges from the ACME server.
func (iss *Issuer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	const prefix = "/.well-known/acme-challenge/"
	path := r.URL.Path
	iss.mu.Lock()
	keyAuth, ok := iss.tokens[strings.TrimPrefix(path, prefix)]
	iss.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, keyAuth)
}

func (iss *Issuer) setToken(token, keyAuth string) {
	iss.mu.Lock()
	iss.tokens[token] = keyAuth
	iss.mu.Unlock()
}

func (iss *Issuer) delToken(token string) {
	iss.mu.Lock()
	delete(iss.tokens, token)
	iss.mu.Unlock()
}

// hasValid reports whether a usable certificate is already cached.
func (iss *Issuer) hasValid(domain string) bool {
	_, _, leaf, err := iss.loadPEM(domain)
	return err == nil && leaf != nil && time.Until(leaf.NotAfter) > 30*24*time.Hour
}

func (iss *Issuer) certFiles(domain string) (certPath, keyPath string) {
	return filepath.Join(iss.dir, domain, "cert.pem"), filepath.Join(iss.dir, domain, "key.pem")
}

// loadPEM reads the cached certificate and its parsed leaf.
func (iss *Issuer) loadPEM(domain string) (certPEM, keyPEM []byte, leaf *x509.Certificate, err error) {
	certPath, keyPath := iss.certFiles(domain)
	certPEM, err = os.ReadFile(certPath)
	if err != nil {
		return nil, nil, nil, err
	}
	keyPEM, err = os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, nil, err
	}
	leaf, err = x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, nil, nil, err
	}
	return certPEM, keyPEM, leaf, nil
}

// Ensure returns a valid certificate for domain, renewing when the cached one
// is missing or due.
func (iss *Issuer) Ensure(domain string) (certPEM, keyPEM []byte, err error) {
	if iss.client == nil {
		return nil, nil, fmt.Errorf("ACME client not started")
	}
	if iss.ln == nil {
		return nil, nil, fmt.Errorf("ACME challenge listener is not running")
	}

	if certPEM, keyPEM, leaf, err := iss.loadPEM(domain); err == nil && time.Until(leaf.NotAfter) > 30*24*time.Hour {
		return certPEM, keyPEM, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	certPEM, keyPEM, err = iss.obtain(ctx, domain)
	if err != nil {
		return nil, nil, err
	}
	if err := iss.store(domain, certPEM, keyPEM); err != nil {
		return nil, nil, err
	}
	log.Printf("[domain] Let's Encrypt certificate obtained for %s", domain)
	return certPEM, keyPEM, nil
}

// accountKey loads the persisted ACME account key, creating one on first run.
func (iss *Issuer) accountKey() (*ecdsa.PrivateKey, error) {
	path := filepath.Join(iss.dir, "account.key")
	if data, err := os.ReadFile(path); err == nil {
		if block, _ := pem.Decode(data); block != nil {
			if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				return key, nil
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		return nil, err
	}
	return key, nil
}

// obtain runs the ACME http-01 flow against the challenge listener.
func (iss *Issuer) obtain(ctx context.Context, domain string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}, key)
	if err != nil {
		return nil, nil, err
	}

	order, err := iss.client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		return nil, nil, fmt.Errorf("authorize: %w", err)
	}
	for _, authzURL := range order.AuthzURLs {
		authz, err := iss.client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return nil, nil, fmt.Errorf("authorization: %w", err)
		}
		if authz.Status == acme.StatusValid {
			continue
		}
		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "http-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			return nil, nil, fmt.Errorf("CA did not offer an http-01 challenge for %s", authz.Identifier.Value)
		}
		keyAuth, err := iss.client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return nil, nil, err
		}
		iss.setToken(chal.Token, keyAuth)
		if _, err := iss.client.Accept(ctx, chal); err != nil {
			iss.delToken(chal.Token)
			return nil, nil, fmt.Errorf("accept challenge: %w", err)
		}
		if _, err := iss.client.WaitAuthorization(ctx, authzURL); err != nil {
			iss.delToken(chal.Token)
			return nil, nil, fmt.Errorf("challenge failed (is %s pointing at this server on port %d?): %w", domain, iss.port, err)
		}
		iss.delToken(chal.Token)
	}

	der, _, err := iss.client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return nil, nil, fmt.Errorf("create order cert: %w", err)
	}
	for _, c := range der {
		b := pem.Block{Type: "CERTIFICATE", Bytes: c}
		certPEM = append(certPEM, pem.EncodeToMemory(&b)...)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

func (iss *Issuer) store(domain string, certPEM, keyPEM []byte) error {
	dir := filepath.Join(iss.dir, domain)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	certPath, keyPath := iss.certFiles(domain)
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return err
	}
	return os.WriteFile(keyPath, keyPEM, 0600)
}
