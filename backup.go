package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// stateFile describes a TunGuard state file that belongs in a backup.
type stateFile struct {
	name     string // name inside the archive
	path     string // absolute path inside DATA_DIR
	perm     os.FileMode
	required bool
}

func (a *API) backupStateFiles() []stateFile {
	return []stateFile{
		{name: "peers.json", path: filepath.Join(a.cfg.DataDir, "peers.json"), perm: 0600, required: true},
		{name: "server_private.key", path: filepath.Join(a.cfg.DataDir, "server_private.key"), perm: 0600, required: true},
		{name: "web_credentials.json", path: filepath.Join(a.cfg.DataDir, "web_credentials.json"), perm: 0600},
		{name: "ssh_host_key", path: filepath.Join(a.cfg.DataDir, "ssh_host_key"), perm: 0600},
		{name: "api_key.json", path: filepath.Join(a.cfg.DataDir, "api_key.json"), perm: 0600},
	}
}

func (a *API) handleBackupDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		jsonErr(w, 405, "GET required")
		return
	}

	tmp, err := os.CreateTemp("", "tanguard-backup-*.tar.gz")
	if err != nil {
		jsonErr(w, 500, "create backup file: "+err.Error())
		return
	}
	defer func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}()

	gz := gzip.NewWriter(tmp)
	tw := tar.NewWriter(gz)

	manifest, _ := json.MarshalIndent(map[string]interface{}{
		"tool":       "tanguard",
		"version":    version,
		"created_at": time.Now().UTC().Format(time.RFC3339),
		"data_dir":   a.cfg.DataDir,
	}, "", "  ")
	if err := writeTarEntry(tw, "manifest.json", manifest, 0600, time.Now()); err != nil {
		jsonErr(w, 500, "write manifest: "+err.Error())
		return
	}

	for _, sf := range a.backupStateFiles() {
		data, err := os.ReadFile(sf.path)
		if err != nil {
			if os.IsNotExist(err) {
				if sf.required {
					log.Printf("[backup] WARNING: required state file %s not found", sf.path)
				}
				continue
			}
			log.Printf("[backup] WARNING: could not read %s: %v", sf.path, err)
			continue
		}
		if err := writeTarEntry(tw, sf.name, data, int64(sf.perm), time.Now()); err != nil {
			jsonErr(w, 500, "write backup entry: "+err.Error())
			return
		}
	}

	if err := tw.Close(); err != nil {
		jsonErr(w, 500, "finalize backup: "+err.Error())
		return
	}
	gz.Close()

	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		jsonErr(w, 500, "rewind backup: "+err.Error())
		return
	}

	filename := "tanguard-backup-" + time.Now().Format("20060102-150405") + ".tar.gz"
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	io.Copy(w, tmp)
	log.Printf("[backup] downloaded by %s", r.RemoteAddr)
}

func (a *API) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
		return
	}

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		jsonErr(w, 400, "invalid multipart form: "+err.Error())
		return
	}
	file, _, err := r.FormFile("backup")
	if err != nil {
		jsonErr(w, 400, "backup file required (multipart field 'backup')")
		return
	}
	defer file.Close()

	tmpDir, err := os.MkdirTemp("", "tanguard-restore-*")
	if err != nil {
		jsonErr(w, 500, "temp dir: "+err.Error())
		return
	}
	defer os.RemoveAll(tmpDir)

	if err := extractTarGz(file, tmpDir); err != nil {
		jsonErr(w, 400, "invalid backup archive: "+err.Error())
		return
	}

	// --- Validate everything before touching live state ---
	var restoredPeers []*PeerRecord
	if data, ok := readBackupFile(tmpDir, "peers.json"); ok {
		if err := json.Unmarshal(data, &restoredPeers); err != nil {
			jsonErr(w, 400, "backup contains an invalid peers.json: "+err.Error())
			return
		}
		for _, p := range restoredPeers {
			if _, err := ValidateHexKey(p.PublicKey); err != nil {
				jsonErr(w, 400, "backup peers.json has an invalid public_key: "+err.Error())
				return
			}
		}
	}

	var restoredKey string
	if data, ok := readBackupFile(tmpDir, "server_private.key"); ok {
		restoredKey = strings.TrimSpace(string(data))
		if _, err := ValidateHexKey(restoredKey); err != nil {
			jsonErr(w, 400, "backup contains an invalid server_private.key: "+err.Error())
			return
		}
		if _, err := PrivToPub(restoredKey); err != nil {
			jsonErr(w, 400, "backup contains an invalid server_private.key: "+err.Error())
			return
		}
	}

	if data, ok := readBackupFile(tmpDir, "web_credentials.json"); ok {
		var c webCredentials
		if err := json.Unmarshal(data, &c); err != nil {
			jsonErr(w, 400, "backup contains an invalid web_credentials.json: "+err.Error())
			return
		}
	}

	if data, ok := readBackupFile(tmpDir, "api_key.json"); ok {
		var k apiKeyRecord
		if err := json.Unmarshal(data, &k); err != nil {
			jsonErr(w, 400, "backup contains an invalid api_key.json: "+err.Error())
			return
		}
	}

	// --- Apply: write state files so a restart reproduces the backup exactly ---
	for _, sf := range a.backupStateFiles() {
		if data, ok := readBackupFile(tmpDir, sf.name); ok {
			if err := writeFile(sf.path, data, sf.perm); err != nil {
				jsonErr(w, 500, "write "+sf.name+": "+err.Error())
				return
			}
		} else if sf.required {
			jsonErr(w, 400, "backup is missing required file "+sf.name)
			return
		} else {
			if err := os.Remove(sf.path); err != nil && !os.IsNotExist(err) {
				log.Printf("[backup] WARNING: could not remove %s: %v", sf.path, err)
			}
		}
	}

	// --- Apply to the running instance ---
	if err := a.store.Load(); err != nil {
		log.Printf("[backup] WARNING: reload peers after restore: %v", err)
	}
	if restoredKey != "" {
		if err := a.wg.Configure(restoredKey, a.cfg.ListenPort); err != nil {
			jsonErr(w, 500, "apply restored server key: "+err.Error())
			return
		}
		if err := writeFile(filepath.Join(a.cfg.DataDir, "server_wg_pubkey.txt"), []byte(a.wg.PublicKey()), 0644); err != nil {
			log.Printf("[backup] WARNING: could not refresh public key file: %v", err)
		}
	}
	if err := a.wg.ApplyAllPeers(); err != nil {
		log.Printf("[backup] WARNING: re-apply peers after restore: %v", err)
	}
	if err := a.creds.Load(); err != nil {
		log.Printf("[backup] WARNING: reload credentials after restore: %v", err)
	}
	if err := a.apiKey.Load(); err != nil {
		log.Printf("[backup] WARNING: reload API key after restore: %v", err)
	}

	log.Printf("[backup] state restored by %s (%d peers)", r.RemoteAddr, len(a.store.All()))
	jsonResp(w, 200, map[string]interface{}{
		"success":           true,
		"peer_count":        len(a.store.All()),
		"server_public_key": a.wg.PublicKey(),
		"restart_required":  false,
	})
}

func writeTarEntry(tw *tar.Writer, name string, data []byte, mode int64, modTime time.Time) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    mode,
		Size:    int64(len(data)),
		ModTime: modTime,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func extractTarGz(r io.Reader, destDir string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("not a valid .tar.gz: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := filepath.Base(filepath.Clean(hdr.Name))
		if name == "" || name == "." {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		dest := filepath.Join(destDir, name)
		f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, tr); err != nil {
			f.Close()
			return err
		}
		f.Close()
	}
	return nil
}

func readBackupFile(dir, name string) ([]byte, bool) {
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil, false
	}
	return data, true
}
