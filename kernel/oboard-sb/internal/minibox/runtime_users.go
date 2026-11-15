package minibox

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/runtimeuser"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/stealth"
	box "github.com/sagernet/sing-box"
)

const (
	maxUserInstallEntries = 8192
	maxUserInstallChunks  = 64
)

var (
	ErrUserInstallIllegal    = errors.New("invalid users install")
	ErrUserInstallIncomplete = errors.New("users install is incomplete")
	ErrUserInstallDigest     = errors.New("users digest mismatch")
	ErrUserInstallBase       = errors.New("users install base revision mismatch")
	ErrUserInstallCapability = errors.New("inbound does not support runtime users")
)

// UserInstallRequest is the body of POST /users/install.
type UserInstallRequest struct {
	Scope         []string           `json:"scope"`
	UsersRevision int64              `json:"users_revision"`
	UsersDigest   string             `json:"users_digest"`
	Mode          string             `json:"mode"`
	BaseRevision  int64              `json:"base_revision,omitempty"`
	Chunk         *UserInstallChunk  `json:"chunk,omitempty"`
	Entries       []UserInstallEntry `json:"entries"`
}

type UserInstallChunk struct {
	Index  int    `json:"index"`
	Total  int    `json:"total"`
	SHA256 string `json:"sha256"`
}

type UserInstallEntry struct {
	InboundTag       string           `json:"inbound_tag"`
	AuthUser         string           `json:"auth_user"`
	Credential       UserCredential   `json:"credential"`
	AuthorizationKey string           `json:"authorization_key"`
	Identity         UserIdentity     `json:"identity"`
	RouteOutbound    string           `json:"route_outbound"`
	Policy           RuntimeUserLimit `json:"policy"`
}

type UserCredential struct {
	UUID     string `json:"uuid,omitempty"`
	Password string `json:"password,omitempty"`
	UserKey  string `json:"userkey,omitempty"`
	PSK      string `json:"psk,omitempty"`
	Flow     string `json:"flow,omitempty"`
}

type UserIdentity struct {
	UserID           int64  `json:"user_id,omitempty"`
	InboundID        int64  `json:"inbound_id,omitempty"`
	PathID           int64  `json:"path_id,omitempty"`
	DeviceIDHash     string `json:"device_id_hash,omitempty"`
	CredentialEpoch  int64  `json:"credential_epoch,omitempty"`
	CredentialStatus string `json:"credential_status,omitempty"`
}

type UserSnapshot struct {
	Revision int64              `json:"users_revision"`
	Digest   string             `json:"users_digest"`
	Scope    []string           `json:"scope"`
	Entries  []UserInstallEntry `json:"entries"`
}

type UsersStatus struct {
	Authentication map[string]map[string]uint64 `json:"authentication,omitempty"`
	UsersRevision  int64                        `json:"users_revision"`
	UsersDigest    string                       `json:"users_digest"`
	BootID         string                       `json:"boot_id"`
	PerInbound     map[string]string            `json:"per_inbound,omitempty"`
}

type persistedUsers struct {
	Current   *UserSnapshot `json:"current,omitempty"`
	Candidate *UserSnapshot `json:"candidate,omitempty"`
	Commit    string        `json:"commit,omitempty"`
	Chunks    *chunkBuffer  `json:"chunks,omitempty"`
}

type chunkBuffer struct {
	Revision int64             `json:"revision"`
	Digest   string            `json:"digest"`
	Mode     string            `json:"mode"`
	Base     int64             `json:"base_revision"`
	Scope    []string          `json:"scope"`
	Total    int               `json:"total"`
	Parts    []json.RawMessage `json:"parts"`
}

// RuntimeUsers applies inbound user tables independently of configuration
// restart. Its durable file is kernel-users.json beside the configuration.
type RuntimeUsers struct {
	mu       sync.Mutex
	path     string
	key      []byte
	bootID   string
	scope    map[string]struct{}
	instance *box.Box
	tracker  *RateLimitTracker
	current  *UserSnapshot
	chunks   *chunkBuffer
}

func NewRuntimeUsers(path string, key []byte, instance *box.Box, tracker *RateLimitTracker, declared []string) *RuntimeUsers {
	scope := map[string]struct{}{}
	for _, tag := range declared {
		tag = strings.TrimSpace(tag)
		if tag != "" {
			scope[tag] = struct{}{}
		}
	}
	return &RuntimeUsers{
		path:     path,
		key:      append([]byte(nil), key...),
		bootID:   newUsersBootID(),
		scope:    scope,
		instance: instance,
		tracker:  tracker,
	}
}

func newUsersBootID() string {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("users-%d", os.Getpid())
	}
	return hex.EncodeToString(raw[:])
}

func (r *RuntimeUsers) Restore() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	state, err := r.load()
	if err != nil {
		return err
	}
	if chunks := state.Chunks; chunks != nil && (state.Current == nil || chunks.Revision > state.Current.Revision) {
		if chunks.Total < 1 || chunks.Total > maxUserInstallChunks || len(chunks.Parts) != chunks.Total {
			return ErrUserInstallIllegal
		}
		for index, part := range chunks.Parts {
			if len(part) == 0 {
				continue
			}
			var entries []UserInstallEntry
			if err := json.Unmarshal(part, &entries); err != nil {
				return ErrUserInstallIllegal
			}
			payload, err := json.Marshal(entries)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(payload)
			req := UserInstallRequest{Scope: chunks.Scope, UsersRevision: chunks.Revision, UsersDigest: chunks.Digest, Mode: chunks.Mode, BaseRevision: chunks.Base, Entries: entries, Chunk: &UserInstallChunk{Index: index, Total: chunks.Total, SHA256: hex.EncodeToString(sum[:])}}
			if err := validateUserInstall(req); err != nil {
				return err
			}
			if _, _, err := r.acceptChunk(req); err != nil {
				return err
			}
		}
	}
	snapshot := state.Current
	// Prepared snapshots have never committed. Recover only the last commit.
	if snapshot == nil {
		if r.tracker != nil && state.Candidate != nil {
			r.tracker.usersFailed.Store(true)
		}
		return nil
	}
	if digest, e := UserSnapshotDigest(snapshot); e != nil || digest != snapshot.Digest {
		return ErrUserInstallDigest
	}
	if r.tracker != nil {
		r.tracker.usersBarrier.Lock()
		defer r.tracker.usersBarrier.Unlock()
	}
	// Configuration restarts may remove runtime-managed listeners. Restore
	// only their surviving scope, but retain the signed snapshot and revision
	// unchanged for rollback and replay protection.
	restored := *snapshot
	restored.Scope = nil
	restored.Entries = nil
	for _, tag := range snapshot.Scope {
		if _, declared := r.scope[tag]; declared {
			restored.Scope = append(restored.Scope, tag)
		}
	}
	for _, entry := range snapshot.Entries {
		if containsString(restored.Scope, entry.InboundTag) && r.canRestoreUser(entry) {
			restored.Entries = append(restored.Entries, entry)
		}
	}
	if err := r.validateSnapshot(&restored); err != nil {
		return err
	}
	if err := r.publishLocked(&restored); err != nil {
		if r.tracker != nil {
			r.tracker.usersFailed.Store(true)
		}
		return err
	}
	r.current = snapshot
	if r.tracker != nil {
		r.tracker.usersFailed.Store(false)
	}
	if state.Commit != "current" {
		return r.persist(persistedUsers{Current: snapshot, Commit: "current"})
	}
	return nil
}

// Stable inbound tags can name a new protocol, and topology edits can remove
// routes. Retain the snapshot for rollback without installing obsolete users.
func (r *RuntimeUsers) canRestoreUser(entry UserInstallEntry) bool {
	if r.instance == nil {
		return false
	}
	if _, ok := r.instance.Outbound().Outbound(entry.RouteOutbound); !ok {
		return false
	}
	c := entry.Credential
	switch r.inboundCapability(entry.InboundTag) {
	case runtimeuser.CapabilitySnellPSK:
		return c.PSK != "" && c.Password == "" && c.UUID == "" && c.UserKey == "" && c.Flow == ""
	case runtimeuser.CapabilityVLESS:
		return c.UUID != "" && c.Password == "" && c.PSK == "" && c.UserKey == ""
	case runtimeuser.CapabilityHysteria2, runtimeuser.CapabilityShadowsocksMulti:
		return c.Password != "" && c.UUID == "" && c.PSK == "" && c.UserKey == "" && c.Flow == ""
	default:
		return false
	}
}

func (r *RuntimeUsers) Status() UsersStatus {
	if r == nil {
		return UsersStatus{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.statusLocked()
}

func (r *RuntimeUsers) Install(req UserInstallRequest) (UsersStatus, error) {
	if r == nil {
		return UsersStatus{}, ErrUserInstallIllegal
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := validateUserInstall(req); err != nil {
		return UsersStatus{}, err
	}
	entries := req.Entries
	if req.Chunk != nil {
		assembled, done, err := r.acceptChunk(req)
		if err != nil {
			return UsersStatus{}, err
		}
		if !done {
			if err := r.persist(persistedUsers{Current: r.current, Chunks: r.chunks, Commit: "chunks"}); err != nil {
				return UsersStatus{}, err
			}
			return r.statusLocked(), ErrUserInstallIncomplete
		}
		entries = assembled
	}
	snapshot, err := r.buildSnapshot(req, entries)
	if err != nil {
		return UsersStatus{}, err
	}
	if r.current != nil {
		if snapshot.Revision < r.current.Revision {
			return UsersStatus{}, ErrUserInstallBase
		}
		if snapshot.Revision == r.current.Revision {
			if snapshot.Digest == r.current.Digest && (r.tracker == nil || !r.tracker.usersFailed.Load()) {
				if err := r.validateSnapshot(snapshot); err != nil {
					return UsersStatus{}, err
				}
				return r.statusLocked(), nil
			}
			if req.Mode != "full" {
				return UsersStatus{}, ErrUserInstallDigest
			}
			currentContent, err := userSnapshotContentDigest(r.current)
			if err != nil {
				return UsersStatus{}, err
			}
			incomingContent, err := userSnapshotContentDigest(snapshot)
			if err != nil {
				return UsersStatus{}, err
			}
			if currentContent != incomingContent {
				return UsersStatus{}, ErrUserInstallDigest
			}
		}
	}
	if r.tracker != nil {
		r.tracker.usersBarrier.Lock()
		defer r.tracker.usersBarrier.Unlock()
	}
	if err := r.validateSnapshot(snapshot); err != nil {
		return UsersStatus{}, err
	}
	if err := r.persist(persistedUsers{Current: r.current, Candidate: snapshot, Commit: "candidate"}); err != nil {
		return UsersStatus{}, err
	}
	fail := func(err error) (UsersStatus, error) {
		if r.tracker != nil {
			r.tracker.usersFailed.Store(true)
			r.tracker.reapSnellParents(true)
		}
		return UsersStatus{}, err
	}
	if err := r.publishLocked(snapshot); err != nil {
		return fail(err)
	}
	if err := r.persist(persistedUsers{Current: snapshot, Commit: "current"}); err != nil {
		return fail(err)
	}
	if r.tracker != nil {
		r.tracker.usersFailed.Store(false)
		r.tracker.reapSnellParents(false)
	}

	r.current = snapshot
	r.chunks = nil
	return r.statusLocked(), nil
}

func (r *RuntimeUsers) statusLocked() UsersStatus {
	out := UsersStatus{BootID: r.bootID, PerInbound: map[string]string{}, Authentication: map[string]map[string]uint64{}}
	if r.current != nil {
		out.UsersRevision = r.current.Revision
		out.UsersDigest = r.current.Digest
		for _, tag := range r.current.Scope {
			out.PerInbound[tag] = r.inboundCapability(tag)
		}
	}
	for tag := range r.scope {
		out.PerInbound[tag] = r.inboundCapability(tag)
		if r.instance != nil {
			if in, ok := r.instance.Inbound().Get(tag); ok {
				if source, ok := in.(interface{ AuthenticationMetrics() map[string]uint64 }); ok {
					if metrics := source.AuthenticationMetrics(); metrics != nil {
						out.Authentication[tag] = metrics
					}
				}
			}
		}
	}
	return out
}

func validateUserInstall(req UserInstallRequest) error {
	if req.UsersRevision <= 0 || strings.TrimSpace(req.UsersDigest) == "" || len(req.UsersDigest) > 128 {
		return ErrUserInstallIllegal
	}
	switch req.Mode {
	case "full", "delta":
	default:
		return ErrUserInstallIllegal
	}
	if len(req.Scope) == 0 || len(req.Scope) > 256 {
		return ErrUserInstallIllegal
	}
	for _, tag := range req.Scope {
		if strings.TrimSpace(tag) == "" {
			return ErrUserInstallIllegal
		}
	}
	if req.Chunk != nil {
		if req.Chunk.Total < 1 || req.Chunk.Total > maxUserInstallChunks || req.Chunk.Index < 0 || req.Chunk.Index >= req.Chunk.Total || req.Chunk.SHA256 == "" {
			return ErrUserInstallIllegal
		}
	}
	if len(req.Entries) > maxUserInstallEntries {
		return ErrUserInstallIllegal
	}
	return nil
}

func (r *RuntimeUsers) acceptChunk(req UserInstallRequest) ([]UserInstallEntry, bool, error) {
	// Defense in depth beside validateUserInstall: the chunk buffer
	// allocation below is only as large as the chunk-count cap.
	if req.Chunk.Total < 1 || req.Chunk.Total > maxUserInstallChunks {
		return nil, false, ErrUserInstallIllegal
	}
	payload, err := json.Marshal(req.Entries)
	if err != nil {
		return nil, false, err
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != strings.ToLower(req.Chunk.SHA256) && hex.EncodeToString(sum[:]) != req.Chunk.SHA256 {
		return nil, false, ErrUserInstallDigest
	}
	if r.chunks == nil || r.chunks.Revision != req.UsersRevision || r.chunks.Digest != req.UsersDigest || r.chunks.Total != req.Chunk.Total {
		r.chunks = &chunkBuffer{
			Revision: req.UsersRevision,
			Digest:   req.UsersDigest,
			Mode:     req.Mode,
			Base:     req.BaseRevision,
			Scope:    append([]string(nil), req.Scope...),
			Total:    req.Chunk.Total,
			Parts:    make([]json.RawMessage, req.Chunk.Total),
		}
	}
	if r.chunks.Mode != req.Mode || r.chunks.Base != req.BaseRevision || !slices.Equal(uniqueSorted(r.chunks.Scope), uniqueSorted(req.Scope)) {
		return nil, false, ErrUserInstallIllegal
	}
	previous := r.chunks.Parts[req.Chunk.Index]
	if len(previous) != 0 && !bytes.Equal(previous, payload) {
		return nil, false, ErrUserInstallIllegal
	}
	totalBytes, totalEntries := len(payload), len(req.Entries)
	for i, part := range r.chunks.Parts {
		if i == req.Chunk.Index || len(part) == 0 {
			continue
		}
		totalBytes += len(part)
		var entries []json.RawMessage
		if json.Unmarshal(part, &entries) != nil {
			return nil, false, ErrUserInstallIllegal
		}
		totalEntries += len(entries)
	}
	if totalBytes > 32<<20 || totalEntries > maxUserInstallEntries {
		return nil, false, ErrUserInstallIllegal
	}
	r.chunks.Parts[req.Chunk.Index] = append(json.RawMessage(nil), payload...)
	for _, part := range r.chunks.Parts {
		if len(part) == 0 {
			return nil, false, nil
		}
	}
	var assembled []UserInstallEntry
	for _, part := range r.chunks.Parts {
		var entries []UserInstallEntry
		if err := json.Unmarshal(part, &entries); err != nil {
			return nil, false, ErrUserInstallIllegal
		}
		assembled = append(assembled, entries...)
	}
	if len(assembled) > maxUserInstallEntries {
		return nil, false, ErrUserInstallIllegal
	}
	return assembled, true, nil
}

func (r *RuntimeUsers) buildSnapshot(req UserInstallRequest, entries []UserInstallEntry) (*UserSnapshot, error) {
	scope := uniqueSorted(req.Scope)
	cleaned := make([]UserInstallEntry, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		entry.InboundTag = strings.TrimSpace(entry.InboundTag)
		entry.AuthUser = strings.TrimSpace(entry.AuthUser)
		if entry.InboundTag == "" || entry.AuthUser == "" {
			return nil, ErrUserInstallIllegal
		}
		key := entry.InboundTag + "\x00" + entry.AuthUser
		if seen[key] {
			return nil, ErrUserInstallIllegal
		}
		seen[key] = true
		deleted := entry.Credential == (UserCredential{})
		if !deleted && strings.TrimSpace(entry.AuthorizationKey) == "" {
			return nil, ErrUserInstallIllegal
		}
		if deleted && (req.Mode != "delta" || entry.AuthorizationKey != "" || entry.Identity != (UserIdentity{}) || entry.Policy != (RuntimeUserLimit{}) || entry.RouteOutbound != "") {
			return nil, ErrUserInstallIllegal
		}
		if !containsString(scope, entry.InboundTag) {
			return nil, ErrUserInstallIllegal
		}
		cleaned = append(cleaned, entry)
	}
	sort.Slice(cleaned, func(i, j int) bool {
		if cleaned[i].InboundTag != cleaned[j].InboundTag {
			return cleaned[i].InboundTag < cleaned[j].InboundTag
		}
		return cleaned[i].AuthUser < cleaned[j].AuthUser
	})
	switch req.Mode {
	case "full":
	case "delta":
		if r.current == nil || r.current.Revision != req.BaseRevision {
			return nil, ErrUserInstallBase
		}
		cleaned = mergeUserEntries(r.current.Entries, cleaned)
	}
	snapshot := &UserSnapshot{Revision: req.UsersRevision, Scope: scope, Entries: cleaned}
	digest, err := UserSnapshotDigest(snapshot)
	if err != nil {
		return nil, err
	}
	if digest != req.UsersDigest {
		return nil, ErrUserInstallDigest
	}
	snapshot.Digest = digest
	return snapshot, nil
}

func mergeUserEntries(base, delta []UserInstallEntry) []UserInstallEntry {
	index := map[string]UserInstallEntry{}
	order := make([]string, 0, len(base)+len(delta))
	keyOf := func(entry UserInstallEntry) string { return entry.InboundTag + "\x00" + entry.AuthUser }
	for _, entry := range base {
		key := keyOf(entry)
		index[key] = entry
		order = append(order, key)
	}
	for _, entry := range delta {
		key := keyOf(entry)
		if _, ok := index[key]; !ok {
			order = append(order, key)
		}
		if entry.Credential == (UserCredential{}) && entry.AuthorizationKey == "" {
			delete(index, key)
			continue
		}
		index[key] = entry
	}
	out := make([]UserInstallEntry, 0, len(index))
	seen := map[string]struct{}{}
	for _, key := range order {
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if entry, ok := index[key]; ok {
			out = append(out, entry)
		}
	}
	return out
}

func UserSnapshotDigest(snapshot *UserSnapshot) (string, error) {
	if snapshot == nil {
		return "", ErrUserInstallIllegal
	}
	return UsersDigest(snapshot.Revision, snapshot.Scope, snapshot.Entries)
}

func userSnapshotContentDigest(snapshot *UserSnapshot) (string, error) {
	stable := make([]UserInstallEntry, len(snapshot.Entries))
	for i, entry := range snapshot.Entries {
		entry.Policy.UsedBaselineBytes = 0
		entry.Policy.LeaseBytes = 0
		entry.Policy.ResetLeaseBytes = 0
		stable[i] = entry
	}
	return UsersDigest(0, snapshot.Scope, stable)
}

// UsersDigest is the shared canonical identity of a user snapshot. Controller
// and Agent compute the same value from the same revision, scope, and entries.
func UsersDigest(revision int64, scope []string, entries []UserInstallEntry) (string, error) {
	sortedScope := uniqueSorted(scope)
	sortedEntries := append([]UserInstallEntry(nil), entries...)
	sort.Slice(sortedEntries, func(i, j int) bool {
		if sortedEntries[i].InboundTag != sortedEntries[j].InboundTag {
			return sortedEntries[i].InboundTag < sortedEntries[j].InboundTag
		}
		return sortedEntries[i].AuthUser < sortedEntries[j].AuthUser
	})
	canonical, err := json.Marshal(struct {
		Revision int64              `json:"users_revision"`
		Scope    []string           `json:"scope"`
		Entries  []UserInstallEntry `json:"entries"`
	}{Revision: revision, Scope: sortedScope, Entries: sortedEntries})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func (r *RuntimeUsers) publishLocked(snapshot *UserSnapshot) error {
	if r.instance == nil {
		return fmt.Errorf("kernel instance is not available")
	}
	byInbound := map[string][]UserInstallEntry{}
	for _, tag := range snapshot.Scope {
		byInbound[tag] = []UserInstallEntry{}
	}
	for _, entry := range snapshot.Entries {
		byInbound[entry.InboundTag] = append(byInbound[entry.InboundTag], entry)
	}
	for tag, entries := range byInbound {
		if len(r.scope) > 0 {
			if _, declared := r.scope[tag]; !declared {
				return fmt.Errorf("%w: %s", ErrUserInstallCapability, tag)
			}
		}
		inbound, ok := r.instance.Inbound().Get(tag)
		if !ok {
			return fmt.Errorf("%w: %s", ErrUserInstallCapability, tag)
		}
		runtimeInbound, ok := inbound.(runtimeuser.Inbound)
		if !ok || runtimeInbound.RuntimeUsersCapability() == "" {
			return fmt.Errorf("%w: %s", ErrUserInstallCapability, tag)
		}
		specs := make([]runtimeuser.Spec, 0, len(entries))
		routes := map[string]string{}
		for _, entry := range entries {
			specs = append(specs, runtimeuser.Spec{
				Name:     entry.AuthUser,
				UUID:     entry.Credential.UUID,
				Password: entry.Credential.Password,
				UserKey:  entry.Credential.UserKey,
				PSK:      entry.Credential.PSK,
				Flow:     entry.Credential.Flow,
			})
			if entry.RouteOutbound != "" {
				routes[entry.AuthUser] = entry.RouteOutbound
			}
		}
		if err := runtimeInbound.UpdateRuntimeUsers(specs); err != nil {
			return err
		}
		if selector, ok := r.instance.Outbound().Outbound(userSelectorTag(tag)); ok {
			if updater, ok := selector.(runtimeuser.Selector); ok {
				if err := updater.UpdateUsers(routes); err != nil {
					return err
				}
			}
		}
	}
	if r.tracker != nil {
		r.tracker.ReplaceScopedUsers(snapshot.Scope, snapshot.Entries)
		r.tracker.publishSnellUsers(snapshot)
	}
	return nil
}

func (r *RuntimeUsers) inboundCapability(tag string) string {
	if r.instance == nil {
		return ""
	}
	inbound, ok := r.instance.Inbound().Get(tag)
	if !ok {
		return ""
	}
	runtimeInbound, ok := inbound.(runtimeuser.Inbound)
	if !ok {
		return ""
	}
	return runtimeInbound.RuntimeUsersCapability()
}

func (r *RuntimeUsers) load() (persistedUsers, error) {
	if r.path == "" {
		return persistedUsers{}, nil
	}
	// #nosec G304 -- path is a fixed file beside the kernel configuration.
	file, err := os.Open(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return persistedUsers{}, nil
		}
		return persistedUsers{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 32*1024*1024+1))
	if len(data) > 32*1024*1024 {
		return persistedUsers{}, ErrUserInstallIllegal
	}
	if err != nil {
		if os.IsNotExist(err) {
			return persistedUsers{}, nil
		}
		return persistedUsers{}, err
	}
	if len(r.key) > 0 && stealth.IsEncrypted(data) {
		if data, err = stealth.Decrypt(r.key, data); err != nil {
			return persistedUsers{}, fmt.Errorf("kernel users state is unreadable")
		}
	}
	var state persistedUsers
	if err := json.Unmarshal(data, &state); err != nil {
		return persistedUsers{}, fmt.Errorf("kernel-users.json is unreadable")
	}
	return state, nil
}

func (r *RuntimeUsers) persist(state persistedUsers) error {
	if r.path == "" {
		return nil
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if len(data) > 32<<20 {
		return ErrUserInstallIllegal
	}
	if len(r.key) > 0 {
		if encrypted, err := stealth.Encrypt(r.key, data); err != nil {
			return err
		} else {
			data = encrypted
		}
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0700); err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, r.path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(r.path))
}

func userSelectorTag(inbound string) string {
	return "userselector-" + inbound
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func (r *RuntimeUsers) validateSnapshot(snapshot *UserSnapshot) error {
	if r.instance == nil {
		return ErrUserInstallCapability
	}
	seen := map[string]bool{}
	names := map[string]bool{}
	keys := map[string]map[string]bool{}
	counts := map[string]int{}
	for _, tag := range snapshot.Scope {
		if _, ok := r.scope[tag]; !ok {
			return ErrUserInstallCapability
		}
		if r.inboundCapability(tag) == "" {
			return ErrUserInstallCapability
		}
	}
	for _, entry := range snapshot.Entries {
		key := entry.InboundTag + "\x00" + entry.AuthUser
		if seen[key] || !containsString(snapshot.Scope, entry.InboundTag) || entry.AuthorizationKey == "" {
			return ErrUserInstallIllegal
		}
		seen[key] = true
		if strings.TrimSpace(entry.AuthUser) != entry.AuthUser || entry.AuthUser == "" || names[entry.AuthUser] {
			return ErrUserInstallIllegal
		}
		names[entry.AuthUser] = true
		if r.tracker != nil {
			if existing := r.tracker.stateForKey("user:" + entry.AuthUser); existing != nil {
				p := existing.loadedPolicy()
				if p.UserID > 0 && (p.UserID != entry.Identity.UserID || p.InboundID != entry.Identity.InboundID || p.PathID != entry.Identity.PathID) {
					return ErrUserInstallIllegal
				}
			}
		}
		if _, ok := r.instance.Outbound().Outbound(entry.RouteOutbound); !ok {
			return ErrUserInstallIllegal
		}
		if r.inboundCapability(entry.InboundTag) == runtimeuser.CapabilitySnellPSK {
			c := entry.Credential
			if len(c.PSK) < 8 || len(c.PSK) > 255 || c.UserKey != "" || c.Password != "" || c.UUID != "" || c.Flow != "" {
				return ErrUserInstallIllegal
			}
			in, _ := r.instance.Inbound().Get(entry.InboundTag)
			if validator, ok := in.(interface{ ValidatePSK(string) error }); ok {
				if err := validator.ValidatePSK(c.PSK); err != nil {
					return err
				}
			}
			counts[entry.InboundTag]++
			if counts[entry.InboundTag] > 64 {
				return fmt.Errorf("snell_credential_limit_exceeded")
			}
			if keys[entry.InboundTag] == nil {
				keys[entry.InboundTag] = map[string]bool{}
			}
			if keys[entry.InboundTag][c.PSK] {
				return fmt.Errorf("snell_duplicate_psk")
			}
			keys[entry.InboundTag][c.PSK] = true
		}
	}
	return nil
}
