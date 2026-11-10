// Copyright (C) 2026 PPanel contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package nowhere

import (
	"context"
	"errors"
	"maps"

	nw "github.com/perfect-panel/nowhere"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy"
)

func (h *Handler) AddUser(ctx context.Context, user *protocol.MemoryUser) error {
	return h.AddUsers(ctx, []*protocol.MemoryUser{user})
}

// AddUsers publishes a complete immutable authentication generation once per
// panel update, avoiding a full user-table rebuild for every individual user.
func (h *Handler) AddUsers(ctx context.Context, users []*protocol.MemoryUser) error {
	h.usersMu.Lock()
	defer h.usersMu.Unlock()
	next := maps.Clone(h.users)
	for _, user := range users {
		if user == nil || user.Email == "" {
			return nw.ErrInvalidUser
		}
		account, ok := user.Account.(*memoryAccount)
		if !ok || !nw.ValidSharedKey([]byte(account.key)) {
			return nw.ErrInvalidSharedKey
		}
		if _, exists := next[user.Email]; exists {
			return errors.New("nowhere: user already exists")
		}
		copyUser := *user
		next[user.Email] = &copyUser
	}
	return h.publishUsers(ctx, next)
}

func (h *Handler) RemoveUser(ctx context.Context, email string) error {
	return h.RemoveUsers(ctx, []string{email})
}
func (h *Handler) RemoveUsers(ctx context.Context, emails []string) error {
	h.usersMu.Lock()
	defer h.usersMu.Unlock()
	next := maps.Clone(h.users)
	for _, email := range emails {
		delete(next, email)
	}
	return h.publishUsers(ctx, next)
}

func (h *Handler) publishUsers(ctx context.Context, next map[string]*protocol.MemoryUser) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := h.ctx.Err(); err != nil {
		return err
	}
	records := make([]nw.User, 0, len(next))
	for name, user := range next {
		records = append(records, nw.User{Name: name, Key: []byte(user.Account.(*memoryAccount).key)})
	}
	update, err := nw.PrepareAuthUpdate(records)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = h.auth.Commit(update); err != nil {
		return err
	}
	h.users = next
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
