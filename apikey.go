package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type apiKeyRecord struct {
	Key       string    `json:"key"`
	CreatedAt time.Time `json:"created_at"`
}

type APIKeyStore struct {
	mu       sync.RWMutex
	filePath string
	record   *apiKeyRecord
}

func NewAPIKeyStore(dataDir string) *APIKeyStore {
	return &APIKeyStore{
		filePath: filepath.Join(dataDir, "api_key.json"),
	}
}

func (s *APIKeyStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			s.record = nil
			return nil
		}
		return fmt.Errorf("read api key: %w", err)
	}

	var rec apiKeyRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return fmt.Errorf("parse api key: %w", err)
	}
	s.record = &rec
	return nil
}

// Exists reports whether an API key has been generated.
func (s *APIKeyStore) Exists() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.record != nil && s.record.Key != ""
}

// Key returns the current API key, if any.
func (s *APIKeyStore) Key() (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.record == nil || s.record.Key == "" {
		return "", false
	}
	return s.record.Key, true
}

// CreatedAt returns when the current key was generated, if any.
func (s *APIKeyStore) CreatedAt() (time.Time, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.record == nil {
		return time.Time{}, false
	}
	return s.record.CreatedAt, true
}

// Verify reports whether the supplied key matches the stored one, using a
// constant-time comparison to avoid timing attacks.
func (s *APIKeyStore) Verify(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.record == nil || s.record.Key == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(s.record.Key), []byte(key)) == 1
}

// Generate creates a new random API key and persists it, immediately
// invalidating any previous key.
func (s *APIKeyStore) Generate() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate api key: %w", err)
	}
	key := hex.EncodeToString(raw)

	rec := &apiKeyRecord{Key: key, CreatedAt: time.Now()}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal api key: %w", err)
	}
	if err := writeFile(s.filePath, data, 0600); err != nil {
		return "", fmt.Errorf("write api key: %w", err)
	}

	s.mu.Lock()
	s.record = rec
	s.mu.Unlock()
	return key, nil
}
