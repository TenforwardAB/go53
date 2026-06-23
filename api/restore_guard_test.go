package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// localAdminRequest builds a request tagged as arriving over the admin socket.
func localAdminRequest(method, path string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	return r.WithContext(context.WithValue(r.Context(), localAdminContextKey{}, true))
}

func TestRestoreGuard(t *testing.T) {
	t.Run("reads are never gated", func(t *testing.T) {
		reached := false
		h := RestoreGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
		// Hold the exclusive lock; a GET must still pass straight through.
		restoreGate.Lock()
		defer restoreGate.Unlock()
		done := make(chan struct{})
		go func() {
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/zones", nil))
			close(done)
		}()
		select {
		case <-done:
			if !reached {
				t.Fatal("GET did not reach handler")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("GET was blocked by the restore gate")
		}
	})

	t.Run("restore excludes concurrent mutations", func(t *testing.T) {
		var inRestore atomic.Bool
		var overlap atomic.Bool
		release := make(chan struct{})

		restore := RestoreGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			inRestore.Store(true)
			<-release // hold the exclusive lock until told to finish
			inRestore.Store(false)
		}))
		mutate := RestoreGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if inRestore.Load() {
				overlap.Store(true)
			}
		}))

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			restore.ServeHTTP(httptest.NewRecorder(), localAdminRequest(http.MethodPost, "/api/restore"))
		}()

		// Wait until the restore is holding the lock.
		deadline := time.After(2 * time.Second)
		for !inRestore.Load() {
			select {
			case <-deadline:
				t.Fatal("restore never started")
			default:
				time.Sleep(time.Millisecond)
			}
		}

		// A mutation issued now must block until the restore releases.
		mutDone := make(chan struct{})
		go func() {
			mutate.ServeHTTP(httptest.NewRecorder(), localAdminRequest(http.MethodPost, "/api/zones/x/records/A"))
			close(mutDone)
		}()

		select {
		case <-mutDone:
			t.Fatal("mutation ran during restore (was not gated)")
		case <-time.After(100 * time.Millisecond):
			// expected: still blocked
		}

		close(release)
		<-mutDone
		wg.Wait()
		if overlap.Load() {
			t.Fatal("mutation overlapped the restore")
		}
	})

	t.Run("non-local-admin restore path does not take the exclusive lock", func(t *testing.T) {
		// Over TCP (no local-admin tag) a /api/restore request is treated as an
		// ordinary mutation (shared lock), so it must not block while another
		// shared holder is active.
		restoreGate.RLock()
		defer restoreGate.RUnlock()
		done := make(chan struct{})
		h := RestoreGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		go func() {
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/restore", nil))
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("TCP /api/restore took the exclusive lock and blocked")
		}
	})
}
