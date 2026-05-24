package privacygateway

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

var ErrSessionNotFound = errors.New("privacy session not found")

type PrivacySession struct {
	RequestID      string
	Response       CompileResponse
	Bindings       []PlaceholderBinding
	Approved       bool
	ApprovalReason string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// SessionStore is private-zone only. It may contain raw values inside bindings,
// so it must never be exposed to the public-zone gateway or serialized to logs.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]PrivacySession
}

func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: map[string]PrivacySession{}}
}

func (s *SessionStore) Put(response CompileResponse, bindings []PlaceholderBinding) (PrivacySession, error) {
	id, err := newRequestID()
	if err != nil {
		return PrivacySession{}, err
	}
	now := time.Now().UTC()
	response.RequestID = id
	session := PrivacySession{
		RequestID: id,
		Response:  response,
		Bindings:  append([]PlaceholderBinding(nil), bindings...),
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = session
	return session, nil
}

func (s *SessionStore) Get(id string) (PrivacySession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[id]
	return session, ok
}

func (s *SessionStore) Approve(id string, approved bool, reason string) (PrivacySession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[id]
	if !ok {
		return PrivacySession{}, ErrSessionNotFound
	}
	session.Approved = approved
	session.ApprovalReason = reason
	session.UpdatedAt = time.Now().UTC()
	s.sessions[id] = session
	return session, nil
}

func newRequestID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
