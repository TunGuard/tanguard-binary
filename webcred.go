package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

type webCredentials struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

type CredentialStore struct {
	mu       sync.RWMutex
	filePath string
	creds    *webCredentials
}

func NewCredentialStore(dataDir string) *CredentialStore {
	return &CredentialStore{
		filePath: filepath.Join(dataDir, "web_credentials.json"),
	}
}

func (s *CredentialStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			s.creds = nil
			return nil
		}
		return fmt.Errorf("read web credentials: %w", err)
	}

	var c webCredentials
	if err := json.Unmarshal(data, &c); err != nil {
		return fmt.Errorf("parse web credentials: %w", err)
	}
	s.creds = &c
	return nil
}

// Exists reports whether custom web dashboard credentials have been set.
func (s *CredentialStore) Exists() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.creds != nil
}

// Username returns the stored custom username, if any.
func (s *CredentialStore) Username() (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.creds == nil {
		return "", false
	}
	return s.creds.Username, true
}

// Verify checks a username/password against the stored credentials.
// The returned bool reports whether custom credentials are in effect.
func (s *CredentialStore) Verify(username, password string) (valid, custom bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.creds == nil {
		return false, false
	}
	if username != s.creds.Username {
		return false, true
	}
	if bcrypt.CompareHashAndPassword([]byte(s.creds.PasswordHash), []byte(password)) != nil {
		return false, true
	}
	return true, true
}

// VerifyWeb reports whether the given username/password are valid for the
// dashboard (and the SSH gateway, which shares the same login). Custom stored
// credentials are used when present; otherwise the configured default web
// login (fallbackUser/fallbackPass) is accepted.
func (s *CredentialStore) VerifyWeb(username, password, fallbackUser, fallbackPass string) bool {
	if valid, custom := s.Verify(username, password); custom {
		return valid
	}
	return username == fallbackUser && password == fallbackPass
}

// Set stores new custom web dashboard credentials and persists them.
func (s *CredentialStore) Set(username, password string) error {
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	s.mu.Lock()
	s.creds = &webCredentials{Username: username, PasswordHash: string(hash)}
	s.mu.Unlock()

	data, err := json.MarshalIndent(s.creds, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal web credentials: %w", err)
	}
	if err := writeFile(s.filePath, data, 0600); err != nil {
		return fmt.Errorf("write web credentials: %w", err)
	}
	return nil
}

// Reset removes custom credentials so the default login is restored.
func (s *CredentialStore) Reset() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(s.filePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove web credentials: %w", err)
	}
	s.creds = nil
	return nil
}
