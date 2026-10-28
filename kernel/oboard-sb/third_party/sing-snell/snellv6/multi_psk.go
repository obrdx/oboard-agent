// SPDX-License-Identifier: GPL-3.0-or-later
package snellv6

import (
	"bytes"
	"context"
	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/internal/reuse"
	"github.com/sagernet/sing-snell/multipsk"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

type PSKService struct {
	manager  *multipsk.Manager
	handler  snell.Handler
	mode     Mode
	mu       sync.RWMutex
	profiles atomic.Value
}

func (s *PSKService) Metrics() *multipsk.Metrics { return &s.manager.Metrics }
func (s *PSKService) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	handshake, finish, err := s.manager.Begin(ctx, conn)
	if err != nil {
		return err
	}
	defer finish(false)
	s.mu.RLock()
	profiles := s.profiles.Load().(map[[32]byte]*Profile)
	users := s.manager.Candidates(source.Addr.String())
	s.mu.RUnlock()
	if len(users) == 0 {
		return multipsk.ErrCredential
	}
	type candidate struct {
		user    *multipsk.Credential
		profile *Profile
		need    int
	}
	candidates := make([]candidate, 0, len(users))
	for _, u := range users {
		p := profiles[u.ID]
		need := snell.SaltLen + snell.HeaderCipherLen
		if s.mode == ModeDefault {
			if p == nil {
				return multipsk.ErrCredential
			}
			need = p.saltBlockLen + p.recordPrefixLen(0) + snell.HeaderCipherLen
		}
		candidates = append(candidates, candidate{u, p, need})
	}
	var input [multipsk.MaxFirstHeader]byte
	size := 0
	var matched *multipsk.Credential
	var profile *Profile
	var salt []byte
	var r reuse.RecordReader
	for len(candidates) > 0 && matched == nil {
		next := len(input)
		for _, c := range candidates {
			next = min(next, c.need)
		}
		if next <= size || next > len(input) {
			return multipsk.ErrCredential
		}
		if _, err = io.ReadFull(conn, input[size:next]); err != nil {
			return err
		}
		size = next
		pending := candidates[:0]
		for _, c := range candidates {
			if c.need > size {
				pending = append(pending, c)
				continue
			}
			offset := snell.SaltLen
			candidateSalt := input[:snell.SaltLen]
			var prefix []byte
			if c.profile != nil {
				extracted := c.profile.extractSalt(input[:c.profile.saltBlockLen])
				candidateSalt = extracted[:]
				offset = c.profile.saltBlockLen
				prefix = input[offset : offset+c.profile.recordPrefixLen(0)]
				offset += len(prefix)
			}
			aead, e := s.manager.Derive(handshake, c.user, candidateSalt)
			if e != nil {
				return e
			}
			plain, e := aead.Open(nil, make([]byte, snell.NonceLen), input[offset:offset+snell.HeaderCipherLen], prefix)
			if e != nil {
				continue
			}
			if plain[0] != snell.HeaderVersion {
				return snell.ErrBadVersion
			}
			matched, profile, salt = c.user, c.profile, append([]byte(nil), candidateSalt...)
			start := snell.SaltLen
			if profile != nil {
				start = profile.saltBlockLen
			}
			upstream := io.MultiReader(bytes.NewReader(append([]byte(nil), input[start:size]...)), conn)
			if profile == nil {
				r = newUnshapedReader(upstream, aead, make([]byte, snell.NonceLen))
			} else {
				shaped := newShapedReader(upstream, matched.PSK, profile)
				shaped.cipher = aead
				r = shaped
			}
			break
		}
		candidates = pending
	}
	if matched == nil {
		return multipsk.ErrCredential
	}

	record, err := r.ReadRecord()
	if err != nil {
		return err
	}
	bound := &Service{psk: matched.PSK, mode: s.mode, profile: profile, handler: s.handler}
	request, record, err := bound.readRequestRecords(r, record)
	if err != nil {
		record.Release()
		return err
	}
	if err = multipsk.CheckReplay(matched, salt); err != nil {
		record.Release()
		return err
	}
	bound.admit = func(requestCtx context.Context) (context.Context, error) {
		admitted, e := s.manager.Admit(requestCtx, matched, conn)
		if e != nil {
			return nil, e
		}
		return auth.ContextWithUser(admitted, matched.Name), nil
	}
	admitted, err := bound.admit(handshake)
	if err != nil {
		record.Release()
		return err
	}
	initialAdmission := admitted
	admitted = auth.ContextWithUser(multipsk.WithRelease(ctx, func() { multipsk.Release(initialAdmission) }), matched.Name)
	s.manager.Remember(source.Addr.String(), matched)
	// The initial request is fully validated before admission and any reply.
	// Reuse performs a fresh admission for every subsequent logical request.
	if request.Command == snell.CommandConnectV2 {
		multipsk.Release(admitted)
		finish(true)
		session := &serverReuseSession[struct{}]{Conn: conn, service: bound, reader: r}
		return session.Serve(ctx, source, onClose, record, request)
	}
	defer multipsk.Release(admitted)
	switch request.Command {
	case snell.CommandConnect:
		if record.IsEmpty() {
			record.Release()
		} else {
			r.SetCache(record)
		}
		finish(true)
		bound.handler.NewConnectionEx(admitted, &serverConn{Conn: conn, service: bound, reader: r}, source, request.Destination, onClose)
		return nil
	case snell.CommandUDP:
		if !record.IsEmpty() {
			record.Release()
			return errInvalidUDPTunnelRequest
		}
		record.Release()
		err = bound.newPacketConnection(admitted, &serverPacketConn{Conn: conn, service: bound, reader: r}, source, onClose)
		if err == nil {
			finish(true)
		}
		return err
	case snell.CommandPing:
		record.Release()
		_, err = writeFirstRecord(conn, s.mode, matched.PSK, profile, []byte{snell.ReplyPong})
		if err == nil {
			finish(true)
		}
		_ = conn.Close()
		return err
	default:
		record.Release()
		return multipsk.ErrCredential
	}
}

func NewPSKService(options ServerOptions, namespace string, admit multipsk.AdmitFunc) (*PSKService, error) {
	if options.Mode != ModeDefault && options.Mode != ModeUnshaped {
		return nil, multipsk.ErrCredential
	}
	s := &PSKService{manager: multipsk.New(namespace, admit), handler: options.Handler, mode: options.Mode}
	s.profiles.Store(map[[32]byte]*Profile{})
	return s, nil
}
func (s *PSKService) UpdatePSKs(users []multipsk.User) error {
	// Serialize snapshot/profile publication against candidate collection.
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.manager.Update(users, 12); err != nil {
		return err
	}
	profiles := map[[32]byte]*Profile{}
	if s.mode == ModeDefault {
		for _, u := range s.manager.Candidates("") {
			profiles[u.ID] = NewProfile(u.PSK)
		}
	}
	s.profiles.Store(profiles)
	return nil
}
