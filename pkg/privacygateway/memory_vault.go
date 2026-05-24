package privacygateway

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

var ErrVaultRecordNotFound = errors.New("vault record not found")

type VaultRecord struct {
	Key       string    `json:"key"`
	Value     string    `json:"value,omitempty"`
	Labels    []string  `json:"labels,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type VaultPutRequest struct {
	Key    string   `json:"key"`
	Value  string   `json:"value"`
	Labels []string `json:"labels,omitempty"`
}

type VaultGetRequest struct {
	Key string `json:"key"`
}

type VaultDeleteRequest struct {
	Key string `json:"key"`
}

type VaultListResponse struct {
	Records []VaultRecord `json:"records"`
}

type EncryptedMemoryVault struct {
	path string
	key  [32]byte
	mu   sync.RWMutex
}

func NewEncryptedMemoryVault(path string, passphrase string) (*EncryptedMemoryVault, error) {
	if path == "" {
		return nil, errors.New("vault path is required")
	}
	if passphrase == "" {
		return nil, errors.New("vault passphrase is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return &EncryptedMemoryVault{path: path, key: sha256.Sum256([]byte(passphrase))}, nil
}

func (v *EncryptedMemoryVault) Put(req VaultPutRequest) (VaultRecord, error) {
	if req.Key == "" {
		return VaultRecord{}, errors.New("vault key is required")
	}
	if req.Value == "" {
		return VaultRecord{}, errors.New("vault value is required")
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	records, err := v.loadLocked()
	if err != nil {
		return VaultRecord{}, err
	}
	now := time.Now().UTC()
	existing := records[req.Key]
	createdAt := existing.CreatedAt
	if createdAt.IsZero() {
		createdAt = now
	}
	record := VaultRecord{
		Key:       req.Key,
		Value:     req.Value,
		Labels:    append([]string(nil), req.Labels...),
		CreatedAt: createdAt,
		UpdatedAt: now,
	}
	records[req.Key] = record
	if err := v.saveLocked(records); err != nil {
		return VaultRecord{}, err
	}
	return record, nil
}

func (v *EncryptedMemoryVault) Get(key string) (VaultRecord, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	records, err := v.loadLocked()
	if err != nil {
		return VaultRecord{}, err
	}
	record, ok := records[key]
	if !ok {
		return VaultRecord{}, ErrVaultRecordNotFound
	}
	return record, nil
}

func (v *EncryptedMemoryVault) Delete(key string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	records, err := v.loadLocked()
	if err != nil {
		return err
	}
	if _, ok := records[key]; !ok {
		return ErrVaultRecordNotFound
	}
	delete(records, key)
	return v.saveLocked(records)
}

func (v *EncryptedMemoryVault) List() ([]VaultRecord, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	records, err := v.loadLocked()
	if err != nil {
		return nil, err
	}
	out := make([]VaultRecord, 0, len(records))
	for _, record := range records {
		record.Value = ""
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func (v *EncryptedMemoryVault) loadLocked() (map[string]VaultRecord, error) {
	data, err := os.ReadFile(v.path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]VaultRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return map[string]VaultRecord{}, nil
	}
	plaintext, err := v.decrypt(data)
	if err != nil {
		return nil, err
	}
	var records map[string]VaultRecord
	if err := json.Unmarshal(plaintext, &records); err != nil {
		return nil, err
	}
	if records == nil {
		records = map[string]VaultRecord{}
	}
	return records, nil
}

func (v *EncryptedMemoryVault) saveLocked(records map[string]VaultRecord) error {
	plaintext, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	ciphertext, err := v.encrypt(plaintext)
	if err != nil {
		return err
	}
	tmp := v.path + ".tmp"
	if err := os.WriteFile(tmp, ciphertext, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, v.path)
}

func (v *EncryptedMemoryVault) encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(v.key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, sealed...), nil
}

func (v *EncryptedMemoryVault) decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(v.key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("vault data is too short")
	}
	nonce := ciphertext[:gcm.NonceSize()]
	data := ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, data, nil)
}
