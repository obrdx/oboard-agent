package authorization

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/stealth"
)

const MaxLifetime = 5 * time.Minute

// maxDeniedKeys bounds the persisted deny watermark so a hostile or buggy
// Controller cannot grow the kernel's memory without limit.
const maxDeniedKeys = 65536

// Lease is the authorization snapshot the Controller issues for one server.
//
// Revision is semantic and advances only when the grant set changes; Sequence
// orders renewals inside one revision; Digest identifies the grant set without
// its renewal deadlines; ExpiresAt bounds the whole lease (never more than
// MaxLifetime after IssuedAt); Denied lists keys that must be refused even if
// an older, still-unexpired lease granted them.
type Lease struct {
	ContinueWhenDisconnected bool              `json:"continue_when_disconnected,omitempty"`
	OfflineGrants            map[string]string `json:"offline_grants,omitempty"`
	Revision                 int64             `json:"revision"`
	Sequence                 int64             `json:"sequence,omitempty"`
	Digest                   string            `json:"digest,omitempty"`
	IssuedAt                 string            `json:"issued_at"`
	ExpiresAt                string            `json:"expires_at,omitempty"`
	Grants                   map[string]string `json:"grants"`
	Denied                   []string          `json:"denied,omitempty"`
}

// window returns the [issued, expires) validity window of the lease.
func (l *Lease) window() (time.Time, time.Time, error) {
	issued, err := time.Parse(time.RFC3339Nano, l.IssuedAt)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	expires := issued.Add(MaxLifetime)
	if l.ExpiresAt != "" {
		parsed, err := time.Parse(time.RFC3339Nano, l.ExpiresAt)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		if parsed.Before(issued) || parsed.After(expires) {
			return time.Time{}, time.Time{}, errors.New("authorization expiry outside the maximum lifetime")
		}
		expires = parsed
	}
	return issued, expires, nil
}

func (l *Lease) Validate() error {
	if l == nil {
		return nil
	}
	issued, expires, err := l.window()
	if err != nil || l.Revision <= 0 || l.Sequence < 0 || len(l.Grants) > 65536 || len(l.Denied) > maxDeniedKeys || len(l.Digest) > 128 {
		return errors.New("invalid authorization snapshot")
	}
	_ = issued
	for key, raw := range l.Grants {
		end, err := time.Parse(time.RFC3339Nano, raw)
		if key == "" || len(key) > 256 || err != nil || end.After(expires) {
			return errors.New("invalid authorization grant")
		}
	}
	if len(l.OfflineGrants) > len(l.Grants) || (!l.ContinueWhenDisconnected && len(l.OfflineGrants) > 0) {
		return errors.New("invalid offline authorization")
	}
	for key, raw := range l.OfflineGrants {
		if _, ok := l.Grants[key]; !ok {
			return errors.New("offline grant without authorization")
		}
		if raw != "" {
			end, err := time.Parse(time.RFC3339Nano, raw)
			grantEnd, _ := time.Parse(time.RFC3339Nano, l.Grants[key])
			if err != nil || end.Before(grantEnd) {
				return errors.New("invalid offline grant deadline")
			}
		}
	}
	for _, key := range l.Denied {
		if key == "" || len(key) > 256 {
			return errors.New("invalid authorization denial")
		}
	}
	return nil
}

// Allows reports whether the lease itself grants key at now. It does not
// consult the deny watermark; Store.Allows does.
func (l *Lease) Allows(key string, now time.Time) bool {
	if key == "" || l == nil {
		return false
	}
	issued, expires, err := l.window()
	if err != nil || now.Before(issued) {
		return false
	}
	if !now.Before(expires) {
		return l.offlineAllows(key, now)
	}
	end, err := time.Parse(time.RFC3339Nano, l.Grants[key])
	return err == nil && !end.After(expires) && now.Before(end)
}

func (l *Lease) offlineAllows(key string, now time.Time) bool {
	if l == nil || !l.ContinueWhenDisconnected {
		return false
	}
	issued, _, err := l.window()
	if err != nil || now.Before(issued) {
		return false
	}
	if _, ok := l.Grants[key]; !ok {
		return false
	}
	raw, ok := l.OfflineGrants[key]
	if !ok {
		return false
	}
	if raw == "" {
		return true
	}
	end, err := time.Parse(time.RFC3339Nano, raw)
	return err == nil && now.Before(end)
}

// NextExpiry returns the earliest instant after now at which some grant or
// the lease itself stops admitting, or zero when nothing is scheduled.
func (l *Lease) NextExpiry(now time.Time) time.Time {
	if l == nil {
		return time.Time{}
	}
	_, expires, err := l.window()
	if err != nil {
		return time.Time{}
	}
	next := expires
	for _, raw := range l.Grants {
		end, err := time.Parse(time.RFC3339Nano, raw)
		if err == nil && end.After(now) && end.Before(next) {
			next = end
		}
	}
	if !next.After(now) {
		return time.Time{}
	}
	return next
}

// deniedEntry records why and when a key was denied so the watermark can be
// pruned once it is provably redundant.
type deniedEntry struct {
	Revision int64  `json:"revision"`
	At       string `json:"at"`
}

// Status is the read-back identity of the installed authorization state.
type Status struct {
	Revision    int64  `json:"revision"`
	Sequence    int64  `json:"sequence"`
	Digest      string `json:"digest,omitempty"`
	IssuedAt    string `json:"issued_at,omitempty"`
	ExpiresAt   string `json:"expires_at,omitempty"`
	BootID      string `json:"boot_id"`
	DeniedCount int    `json:"denied_count"`
	GrantCount  int    `json:"grant_count"`
}

// Store never lets configuration replay or rollback replace a newer full
// snapshot, and never lets any snapshot re-admit a denied key.
type Store struct {
	mu   sync.Mutex
	path string
	// key encrypts the lease and deny files at rest when set (stealth mode).
	key          []byte
	disconnected bool
	loaded       bool
	err          error
	lease        *Lease
	denied       map[string]deniedEntry
	bootID       string
	now          func() time.Time
	// onChange is invoked (outside the lock) after the installed state changed.
	onChange func()
}

// NewStore creates a lease store at path. A non-empty key stores the lease
// and deny watermark as encrypted envelopes (stealth mode); an empty key
// keeps plaintext JSON.
func NewStore(path string, key []byte) *Store {
	return &Store{path: path, key: append([]byte(nil), key...), denied: map[string]deniedEntry{}, bootID: newBootID(), now: time.Now}
}

// SetChangeHook registers a callback that runs after the installed lease or
// deny watermark changed.
func (s *Store) SetChangeHook(fn func()) {
	s.mu.Lock()
	s.onChange = fn
	s.mu.Unlock()
}

// SetClock overrides the clock used for deny watermark bookkeeping.
func (s *Store) SetClock(now func() time.Time) {
	s.mu.Lock()
	if now != nil {
		s.now = now
	}
	s.mu.Unlock()
}

func newBootID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("boot-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// BootID identifies this Store instance (this process lifetime).
func (s *Store) BootID() string { return s.bootID }

func clone(l *Lease) *Lease {
	if l == nil {
		return nil
	}
	out := *l
	out.Grants = make(map[string]string, len(l.Grants))
	for k, v := range l.Grants {
		out.Grants[k] = v
	}
	out.OfflineGrants = nil
	if l.OfflineGrants != nil {
		out.OfflineGrants = make(map[string]string, len(l.OfflineGrants))
		for k, v := range l.OfflineGrants {
			out.OfflineGrants[k] = v
		}
	}
	out.Denied = append([]string(nil), l.Denied...)
	return &out
}

func (s *Store) deniedPath() string {
	if s.path == "" {
		return ""
	}
	return s.path + ".denied.json"
}

func (s *Store) load() {
	if s.loaded {
		return
	}
	s.loaded = true
	if s.path == "" {
		return
	}
	data, err := s.readState(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		s.err = err
		return
	default:
		var l Lease
		if err := json.Unmarshal(data, &l); err != nil {
			s.err = err
			return
		}
		if err := l.Validate(); err != nil {
			s.err = err
			return
		}
		s.lease = clone(&l)
	}
	deniedData, err := s.readState(s.deniedPath())
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		s.err = err
		return
	}
	denied := map[string]deniedEntry{}
	if err := json.Unmarshal(deniedData, &denied); err != nil {
		s.err = err
		return
	}
	if len(denied) > maxDeniedKeys {
		s.err = errors.New("authorization deny watermark exceeds bounds")
		return
	}
	s.denied = denied
}

func (s *Store) Snapshot() (*Lease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.load()
	return clone(s.lease), s.err
}

// Status returns the installed identity without any grant content.
func (s *Store) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.load()
	out := Status{BootID: s.bootID, DeniedCount: len(s.denied)}
	if s.lease != nil {
		out.Revision = s.lease.Revision
		out.Sequence = s.lease.Sequence
		out.Digest = s.lease.Digest
		out.IssuedAt = s.lease.IssuedAt
		out.ExpiresAt = s.lease.ExpiresAt
		out.GrantCount = len(s.lease.Grants)
	}
	return out
}

// Allows checks the deny watermark first, then the installed lease.
func (s *Store) Allows(key string, now time.Time) bool {
	if key == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.load()
	if s.err != nil {
		return false
	}
	if _, denied := s.denied[key]; denied {
		return false
	}
	return s.lease.Allows(key, now)
}

// OfflineAllows permits local quota fallback only for explicitly authorized keys
// while the control link is down or its signed snapshot can no longer renew.
func (s *Store) OfflineAllows(key string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.load()
	if s.err != nil || s.lease == nil {
		return false
	}
	if _, denied := s.denied[key]; denied {
		return false
	}
	_, expires, err := s.lease.window()
	return err == nil && (s.disconnected || !now.Before(expires)) && s.lease.offlineAllows(key, now)
}

func (s *Store) SetDisconnected(disconnected bool) {
	s.mu.Lock()
	s.disconnected = disconnected
	hook := s.onChange
	s.mu.Unlock()
	if hook != nil {
		hook()
	}
}

// Denied reports whether key is on the deny watermark.
func (s *Store) Denied(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.load()
	_, denied := s.denied[key]
	return denied
}

// DeniedKeys returns the deny watermark keys in sorted order.
func (s *Store) DeniedKeys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.load()
	out := make([]string, 0, len(s.denied))
	for key := range s.denied {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// ErrConflict is returned when a snapshot reuses an installed identity with
// different content. The caller must not treat it as a benign replay.
var ErrConflict = errors.New("authorization snapshot identity reused with different content")

// UpdateResult tells the caller what an Update did.
type UpdateResult struct {
	Installed  bool
	Superseded bool
	Unchanged  bool
	// Revoked lists keys that were granted before and are not granted now,
	// including keys the incoming lease explicitly denies.
	Revoked []string
}

// Update installs a newer snapshot. Ordering is (revision, sequence, issued_at):
// an older or equal-and-older identity is reported as superseded and ignored,
// an equal identity with different content is ErrConflict, and a lease whose
// issuance lies at or after the installed lease's expiry is accepted even with
// a lower revision, because the installed lease can no longer admit anyone
// and a Controller restore may legitimately restart its counters.
func (s *Store) Update(incoming *Lease) error {
	_, err := s.UpdateWithResult(incoming)
	return err
}

func (s *Store) UpdateWithResult(incoming *Lease) (UpdateResult, error) {
	s.mu.Lock()
	result, hook, err := s.updateLocked(incoming)
	s.mu.Unlock()
	if hook != nil {
		hook()
	}
	return result, err
}

func (s *Store) updateLocked(incoming *Lease) (UpdateResult, func(), error) {
	s.load()
	if s.err != nil {
		return UpdateResult{}, nil, fmt.Errorf("authorization state unreadable: %w", s.err)
	}
	if incoming == nil {
		return UpdateResult{Unchanged: true}, nil, nil
	}
	if err := incoming.Validate(); err != nil {
		return UpdateResult{}, nil, err
	}
	candidate := clone(incoming)
	if s.lease != nil {
		switch s.compare(candidate) {
		case orderOlder:
			return UpdateResult{Superseded: true}, nil, nil
		case orderEqual:
			if !reflect.DeepEqual(candidate.Grants, s.lease.Grants) || candidate.Digest != s.lease.Digest || candidate.ContinueWhenDisconnected != s.lease.ContinueWhenDisconnected || !reflect.DeepEqual(candidate.OfflineGrants, s.lease.OfflineGrants) {
				return UpdateResult{}, nil, ErrConflict
			}
			if len(candidate.Denied) == 0 {
				return UpdateResult{Unchanged: true}, nil, nil
			}
		case orderConflict:
			return UpdateResult{}, nil, ErrConflict
		}
	}
	now := s.now().UTC()
	revoked := map[string]struct{}{}
	if s.lease != nil {
		for key := range s.lease.Grants {
			if _, still := candidate.Grants[key]; !still {
				revoked[key] = struct{}{}
			}
		}
	}
	for _, key := range candidate.Denied {
		if _, granted := candidate.Grants[key]; granted {
			// A key both granted and denied in one snapshot is a Controller
			// bug; deny wins because denial is the safe direction.
			delete(candidate.Grants, key)
			delete(candidate.OfflineGrants, key)
		}
		if len(s.denied) < maxDeniedKeys {
			s.denied[key] = deniedEntry{Revision: candidate.Revision, At: now.Format(time.RFC3339Nano)}
		}
		revoked[key] = struct{}{}
	}
	// Denials older than the maximum lifetime and below the installed
	// revision are redundant: no lease that could grant them can still exist.
	for key, entry := range s.denied {
		if _, granted := candidate.Grants[key]; granted {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, entry.At)
		if err == nil && entry.Revision < candidate.Revision && now.Sub(at) > MaxLifetime {
			delete(s.denied, key)
		}
	}
	if s.path != "" {
		data, err := json.Marshal(candidate)
		if err != nil {
			return UpdateResult{}, nil, err
		}
		if err := s.writeState(s.path, data); err != nil {
			s.err = err
			return UpdateResult{}, nil, err
		}
		deniedData, err := json.Marshal(s.denied)
		if err != nil {
			return UpdateResult{}, nil, err
		}
		if err := s.writeState(s.deniedPath(), deniedData); err != nil {
			s.err = err
			return UpdateResult{}, nil, err
		}
	}
	s.lease = candidate
	out := UpdateResult{Installed: true}
	for key := range revoked {
		out.Revoked = append(out.Revoked, key)
	}
	sort.Strings(out.Revoked)
	return out, s.onChange, nil
}

// Deny adds keys to the watermark without installing a snapshot. It is the
// emergency path: the keys are refused immediately and stay refused until a
// later full snapshot has made the denial redundant.
func (s *Store) Deny(keys []string, revision int64) error {
	s.mu.Lock()
	s.load()
	if s.err != nil {
		s.mu.Unlock()
		return fmt.Errorf("authorization state unreadable: %w", s.err)
	}
	now := s.now().UTC().Format(time.RFC3339Nano)
	changed := false
	for _, key := range keys {
		if key == "" || len(key) > 256 {
			continue
		}
		if existing, ok := s.denied[key]; ok && existing.Revision >= revision {
			continue
		}
		if len(s.denied) >= maxDeniedKeys {
			break
		}
		s.denied[key] = deniedEntry{Revision: revision, At: now}
		changed = true
	}
	var hook func()
	if changed {
		if s.path != "" {
			data, err := json.Marshal(s.denied)
			if err != nil {
				s.mu.Unlock()
				return err
			}
			if err := s.writeState(s.deniedPath(), data); err != nil {
				s.err = err
				s.mu.Unlock()
				return err
			}
		}
		hook = s.onChange
	}
	s.mu.Unlock()
	if hook != nil {
		hook()
	}
	return nil
}

type leaseOrder int

const (
	orderNewer leaseOrder = iota
	orderOlder
	orderEqual
	orderConflict
)

// compare orders candidate against the installed lease.
func (s *Store) compare(candidate *Lease) leaseOrder {
	current := s.lease
	curIssued, curExpires, _ := current.window()
	candIssued, _, _ := candidate.window()
	if candidate.Revision > current.Revision {
		return orderNewer
	}
	if candidate.Revision < current.Revision {
		if !candIssued.Before(curExpires) {
			return orderNewer
		}
		return orderOlder
	}
	// Same revision: the grant set must be identical unless the installed
	// lease has fully expired and a Controller reset re-issued the number.
	if candidate.Digest != "" && current.Digest != "" && candidate.Digest != current.Digest {
		if !candIssued.Before(curExpires) {
			return orderNewer
		}
		return orderConflict
	}
	if candidate.Sequence > 0 && current.Sequence > 0 {
		switch {
		case candidate.Sequence > current.Sequence:
			return orderNewer
		case candidate.Sequence < current.Sequence:
			return orderOlder
		}
		if candIssued.Equal(curIssued) {
			return orderEqual
		}
		return orderConflict
	}
	switch {
	case candIssued.After(curIssued):
		return orderNewer
	case candIssued.Before(curIssued):
		return orderOlder
	default:
		return orderEqual
	}
}

// readState reads a store file, decrypting it when the store holds a key.
// A plaintext file is returned as-is so a crash mid-migration cannot wedge
// the store.
func (s *Store) readState(path string) ([]byte, error) {
	// #nosec G304 -- path is the store path derived from the config directory.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(s.key) > 0 && stealth.IsEncrypted(data) {
		return stealth.Decrypt(s.key, data)
	}
	return data, nil
}

// writeState writes a store file, encrypting it when the store holds a key.
func (s *Store) writeState(path string, data []byte) error {
	if len(s.key) > 0 {
		encrypted, err := stealth.Encrypt(s.key, data)
		if err != nil {
			return err
		}
		data = encrypted
	}
	return writeAtomic(path, data)
}

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".authorization-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
