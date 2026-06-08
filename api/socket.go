// Package api
// This file is part of the go53 project.
//
// This file is licensed under the European Union Public License (EUPL) v1.2.
// You may only use this work in compliance with the License.
// You may obtain a copy of the License at:
//
//	https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed "as is",
// without any warranty or conditions of any kind.
//
// Copyleft (c) 2025 - Tenforward AB. All rights reserved.
//
// This file: socket.go is part of the go53 authoritative DNS server.
package api

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"go53/config"
)

// adminSocketMode is the permission mode applied to the admin socket: owner and
// group read/write, no access for others. Combined with group ownership by
// AdminSocketGroup this restricts local admin to root and that group's members.
const adminSocketMode os.FileMode = 0o660

// localAdminContextKey marks requests that arrived over the trusted local admin
// Unix socket. Such requests are gated by filesystem permissions rather than by API
// token auth, so they are the break-glass administration path used when the external
// IdP is unreachable. AuthMiddleware can consult IsLocalAdmin to skip token checks,
// but the socket handler is already served without that middleware.
type localAdminContextKey struct{}

// IsLocalAdmin reports whether the request arrived over the trusted admin socket.
func IsLocalAdmin(ctx context.Context) bool {
	v, _ := ctx.Value(localAdminContextKey{}).(bool)
	return v
}

// StartAdminSocket serves the full admin API over a Unix domain socket and blocks
// until the listener stops, so callers run it in its own goroutine.
//
// Access is controlled purely by filesystem permissions: the socket is created with
// mode 0660 and, when the configured group exists, group-owned by it (default
// go53_admin) so that root and members of that group can administer go53 locally
// without API tokens. Requests served here intentionally bypass the API auth
// middleware — this is the local break-glass path. Every failure is logged but
// non-fatal so a misconfigured socket can never take the node down.
func StartAdminSocket(cfg config.BaseConfig) {
	path := strings.TrimSpace(cfg.AdminSocket)
	if path == "" {
		log.Println("admin socket: disabled (ADMIN_SOCKET empty)")
		return
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		log.Printf("admin socket: cannot create directory for %s: %v", path, err)
		return
	}
	// Remove a stale socket left behind by a previous run or crash before re-binding.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		log.Printf("admin socket: cannot remove stale socket %s: %v", path, err)
		return
	}

	listener, err := net.Listen("unix", path)
	if err != nil {
		log.Printf("admin socket: failed to listen on %s: %v", path, err)
		return
	}

	if err := os.Chmod(path, adminSocketMode); err != nil {
		log.Printf("admin socket: cannot chmod %s: %v", path, err)
	}
	applyAdminSocketGroup(path, cfg.AdminSocketGroup)

	handler := localAdminTag(NewRouter(cfg))
	srv := &http.Server{Handler: handler}
	log.Printf("Starting admin API on unix socket %s (group %q, mode %#o)", path, cfg.AdminSocketGroup, adminSocketMode)
	if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Printf("admin socket: server stopped: %v", err)
	}
}

// applyAdminSocketGroup chowns the socket to the given group so its members can
// administer go53 locally. A missing group is not fatal: the socket keeps its
// default ownership (owner-only effective access via mode 0660).
func applyAdminSocketGroup(path, group string) {
	group = strings.TrimSpace(group)
	if group == "" {
		return
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		log.Printf("admin socket: group %q not found, leaving owner-only access: %v", group, err)
		return
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		log.Printf("admin socket: invalid gid %q for group %q: %v", g.Gid, group, err)
		return
	}
	if err := os.Chown(path, -1, gid); err != nil {
		log.Printf("admin socket: cannot chown %s to group %q: %v", path, group, err)
	}
}

// localAdminTag marks every request served over the admin socket as local admin so
// downstream code can distinguish break-glass traffic from token-authenticated TCP.
func localAdminTag(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), localAdminContextKey{}, true)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// WrapLocalAdminTag is the exported form of localAdminTag for use in tests.
func WrapLocalAdminTag(next http.Handler) http.Handler {
	return localAdminTag(next)
}
