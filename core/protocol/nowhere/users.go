// Copyright (C) 2026 PPanel contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package nowhere

import (
	"context"
	"errors"

	nw "github.com/perfect-panel/nowhere"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy"
)

func (h *Handler) AddUser(ctx context.Context, user *protocol.MemoryUser) error {
	return h.AddUsers(ctx, []*protocol.MemoryUser{user})
}

// AddUsers stages only the changed credentials. Readers do not wait while
// keys or copy-on-write index shards are prepared; publication holds usersMu
// only for the final authentication swap and map edits.
func (h *Handler) AddUsers(ctx context.Context, users []*protocol.MemoryUser) error {
	h.userUpdateMu.Lock()
	defer h.userUpdateMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	records := make([]nw.User, 0, len(users))
	copies := make(map[string]*protocol.MemoryUser, len(users))
	for _, user := range users {
		if user == nil || user.Email == "" {
			return nw.ErrInvalidUser
		}
		account, ok := user.Account.(*memoryAccount)
		if !ok || !nw.ValidSharedKey([]byte(account.key)) {
			return nw.ErrInvalidSharedKey
		}
		if _, exists := copies[user.Email]; exists {
			return errors.New("nowhere: duplicate user identity")
		}
		copyUser := *user
		copies[user.Email] = &copyUser
		records = append(records, nw.User{Name: user.Email, Key: []byte(account.key)})
	}
	h.usersMu.RLock()
	duplicate := false
	for name := range copies {
		if _, exists := h.users[name]; exists {
			duplicate = true
			break
		}
	}
	h.usersMu.RUnlock()
	if duplicate {
		return errors.New("nowhere: user already exists")
	}
	update, err := h.auth.PrepareChanges(records, nil)
	if err != nil {
		return err
	}
	if err = h.publishChanges(ctx, update, copies, nil); err != nil {
		return err
	}
	return nil
}

func (h *Handler) RemoveUser(ctx context.Context, email string) error {
	return h.RemoveUsers(ctx, []string{email})
}
func (h *Handler) RemoveUsers(ctx context.Context, emails []string) error {
	h.userUpdateMu.Lock()
	defer h.userUpdateMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	update, err := h.auth.PrepareChanges(nil, emails)
	if err != nil {
		return err
	}
	return h.publishChanges(ctx, update, nil, emails)
}

func (h *Handler) publishChanges(ctx context.Context, update *nw.AuthUpdate, added map[string]*protocol.MemoryUser, removed []string) error {
	h.usersMu.Lock()
	if err := ctx.Err(); err != nil {
		h.usersMu.Unlock()
		return err
	}
	if err := h.ctx.Err(); err != nil {
		h.usersMu.Unlock()
		return err
	}
	if err := h.auth.Commit(update); err != nil {
		h.usersMu.Unlock()
		return err
	}
	for _, name := range removed {
		delete(h.users, name)
	}
	for name, user := range added {
		h.users[name] = user
	}
	h.usersMu.Unlock()
	h.registry.CloseStale(h.auth)
	return nil
}

func (h *Handler) GetUser(_ context.Context, email string) *protocol.MemoryUser {
	h.usersMu.RLock()
	defer h.usersMu.RUnlock()
	user := h.users[email]
	if user == nil {
		return nil
	}
	copyUser := *user
	return &copyUser
}
func (h *Handler) GetUsers(context.Context) []*protocol.MemoryUser {
	h.usersMu.RLock()
	defer h.usersMu.RUnlock()
	users := make([]*protocol.MemoryUser, 0, len(h.users))
	for _, user := range h.users {
		copyUser := *user
		users = append(users, &copyUser)
	}
	return users
}
func (h *Handler) GetUsersCount(context.Context) int64 {
	h.usersMu.RLock()
	defer h.usersMu.RUnlock()
	return int64(len(h.users))
}

var _ proxy.UserManager = (*Handler)(nil)
