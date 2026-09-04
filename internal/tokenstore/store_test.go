package tokenstore

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/edspc/vault-oauth2-credentials-agent/internal/oauth2"
	"github.com/edspc/vault-oauth2-credentials-agent/internal/vault"
)

var (
	testLocation = Location{Mount: "secret", Path: "oauth2/example"}
	testNow      = time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
)

// fakeVault is an in-memory KV v2 backend with check-and-set semantics.
type fakeVault struct {
	mu      sync.Mutex
	data    map[string]any
	version int
	writes  int
	// beforeWrite runs inside WriteKV2 and can simulate a concurrent writer.
	beforeWrite func()
	readErr     error
	writeErr    error
}

func (f *fakeVault) ReadKV2(_ context.Context, _, _ string) (*vault.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readErr != nil {
		return nil, f.readErr
	}
	if f.data == nil {
		return nil, vault.ErrSecretNotFound
	}
	copied := make(map[string]any, len(f.data))
	for k, v := range f.data {
		copied[k] = v
	}
	return &vault.Secret{Data: copied, Version: f.version}, nil
}

func (f *fakeVault) WriteKV2(_ context.Context, _, _ string, data map[string]any, cas int) (int, error) {
	if f.beforeWrite != nil {
		hook := f.beforeWrite
		f.beforeWrite = nil
		hook()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes++
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	if cas != f.version {
		return 0, vault.ErrCASMismatch
	}
	f.data = data
	f.version++
	return f.version, nil
}

func newTestStore(api API) *Store {
	return New(api, WithClock(func() time.Time { return testNow }))
}

func TestSaveAuthorizedStoresAllFields(t *testing.T) {
	backend := &fakeVault{}
	store := newTestStore(backend)

	token := &oauth2.Token{
		AccessToken:  "at",
		RefreshToken: "rt",
		TokenType:    "Bearer",
		Expiry:       testNow.Add(time.Hour),
		Scope:        "repo",
		Extra:        map[string]any{"id_token": "idt"},
	}
	record, err := store.SaveAuthorized(context.Background(), testLocation, "example", token)
	if err != nil {
		t.Fatalf("SaveAuthorized() error = %v", err)
	}
	if !record.ObtainedAt.Equal(testNow) {
		t.Errorf("ObtainedAt = %s, want %s", record.ObtainedAt, testNow)
	}

	stored := backend.data
	want := map[string]string{
		FieldAccessToken:  "at",
		FieldRefreshToken: "rt",
		FieldTokenType:    "Bearer",
		FieldScope:        "repo",
		FieldEntryID:      "example",
		FieldExpiry:       testNow.Add(time.Hour).Format(time.RFC3339),
		FieldObtainedAt:   testNow.Format(time.RFC3339),
		FieldUpdatedAt:    testNow.Format(time.RFC3339),
		FieldExtra:        `{"id_token":"idt"}`,
	}
	for field, value := range want {
		if stored[field] != value {
			t.Errorf("stored %q = %v, want %q", field, stored[field], value)
		}
	}
}

func TestLoadRoundTrip(t *testing.T) {
	backend := &fakeVault{}
	store := newTestStore(backend)
	ctx := context.Background()

	token := &oauth2.Token{
		AccessToken:  "at",
		RefreshToken: "rt",
		TokenType:    "Bearer",
		Expiry:       testNow.Add(time.Hour),
		Scope:        "repo read:org",
		Extra:        map[string]any{"id_token": "idt"},
	}
	if _, err := store.SaveAuthorized(ctx, testLocation, "example", token); err != nil {
		t.Fatalf("SaveAuthorized() error = %v", err)
	}

	loaded, err := store.Load(ctx, testLocation)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.AccessToken != "at" || loaded.RefreshToken != "rt" {
		t.Errorf("loaded = %+v, want at/rt", loaded)
	}
	if !loaded.Expiry.Equal(token.Expiry) {
		t.Errorf("Expiry = %s, want %s", loaded.Expiry, token.Expiry)
	}
	if loaded.Extra["id_token"] != "idt" {
		t.Errorf("Extra = %v, want id_token=idt", loaded.Extra)
	}
	if got := loaded.Token(); got.AccessToken != "at" || got.Scope != "repo read:org" {
		t.Errorf("Token() = %+v, want the stored values", got)
	}
}

func TestLoadNotFound(t *testing.T) {
	store := newTestStore(&fakeVault{})
	_, err := store.Load(context.Background(), testLocation)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Load() error = %v, want ErrNotFound", err)
	}
}

func TestSaveRefreshedKeepsPreviousRefreshTokenAndObtainedAt(t *testing.T) {
	backend := &fakeVault{}
	store := newTestStore(backend)
	ctx := context.Background()

	first := &oauth2.Token{AccessToken: "at1", RefreshToken: "rt1", Scope: "repo",
		Expiry: testNow.Add(time.Hour)}
	if _, err := store.SaveAuthorized(ctx, testLocation, "example", first); err != nil {
		t.Fatalf("SaveAuthorized() error = %v", err)
	}

	later := testNow.Add(50 * time.Minute)
	store.now = func() time.Time { return later }

	// A provider that does not rotate refresh tokens returns none.
	refreshed := &oauth2.Token{AccessToken: "at2", Expiry: later.Add(time.Hour)}
	record, err := store.SaveRefreshed(ctx, testLocation, "example", refreshed)
	if err != nil {
		t.Fatalf("SaveRefreshed() error = %v", err)
	}
	if record.RefreshToken != "rt1" {
		t.Errorf("RefreshToken = %q, want the previous rt1 to be kept", record.RefreshToken)
	}
	if record.Scope != "repo" {
		t.Errorf("Scope = %q, want the previous scope to be kept", record.Scope)
	}
	if !record.ObtainedAt.Equal(testNow) {
		t.Errorf("ObtainedAt = %s, want the original %s", record.ObtainedAt, testNow)
	}
	if !record.UpdatedAt.Equal(later) {
		t.Errorf("UpdatedAt = %s, want %s", record.UpdatedAt, later)
	}
}

func TestSaveRefreshedTakesRotatedRefreshToken(t *testing.T) {
	backend := &fakeVault{}
	store := newTestStore(backend)
	ctx := context.Background()

	if _, err := store.SaveAuthorized(ctx, testLocation, "example",
		&oauth2.Token{AccessToken: "at1", RefreshToken: "rt1"}); err != nil {
		t.Fatalf("SaveAuthorized() error = %v", err)
	}
	record, err := store.SaveRefreshed(ctx, testLocation, "example",
		&oauth2.Token{AccessToken: "at2", RefreshToken: "rt2"})
	if err != nil {
		t.Fatalf("SaveRefreshed() error = %v", err)
	}
	if record.RefreshToken != "rt2" {
		t.Errorf("RefreshToken = %q, want the rotated rt2", record.RefreshToken)
	}
}

func TestSaveAuthorizedResetsObtainedAt(t *testing.T) {
	store := newTestStore(&fakeVault{})
	ctx := context.Background()

	if _, err := store.SaveAuthorized(ctx, testLocation, "example",
		&oauth2.Token{AccessToken: "at1", RefreshToken: "rt1"}); err != nil {
		t.Fatalf("SaveAuthorized() error = %v", err)
	}
	later := testNow.Add(24 * time.Hour)
	store.now = func() time.Time { return later }

	record, err := store.SaveAuthorized(ctx, testLocation, "example",
		&oauth2.Token{AccessToken: "at2", RefreshToken: "rt2"})
	if err != nil {
		t.Fatalf("SaveAuthorized() error = %v", err)
	}
	if !record.ObtainedAt.Equal(later) {
		t.Errorf("ObtainedAt = %s, want it reset to %s", record.ObtainedAt, later)
	}
}

func TestSaveRetriesOnCASMismatch(t *testing.T) {
	backend := &fakeVault{data: map[string]any{FieldAccessToken: "old"}, version: 1}
	store := newTestStore(backend)

	// A concurrent writer bumps the version between the read and the write.
	backend.beforeWrite = func() {
		backend.mu.Lock()
		backend.version = 2
		backend.mu.Unlock()
	}

	record, err := store.SaveRefreshed(context.Background(), testLocation, "example",
		&oauth2.Token{AccessToken: "at", RefreshToken: "rt"})
	if err != nil {
		t.Fatalf("SaveRefreshed() error = %v", err)
	}
	if record.AccessToken != "at" {
		t.Errorf("AccessToken = %q, want at", record.AccessToken)
	}
	if backend.writes != 2 {
		t.Errorf("writes = %d, want the write to be retried once", backend.writes)
	}
}

func TestSaveGivesUpAfterRepeatedCASMismatch(t *testing.T) {
	backend := &fakeVault{data: map[string]any{}, version: 1, writeErr: vault.ErrCASMismatch}
	store := newTestStore(backend)

	_, err := store.SaveRefreshed(context.Background(), testLocation, "example",
		&oauth2.Token{AccessToken: "at"})
	if !errors.Is(err, vault.ErrCASMismatch) {
		t.Fatalf("SaveRefreshed() error = %v, want ErrCASMismatch", err)
	}
	if backend.writes != 2 {
		t.Errorf("writes = %d, want exactly two attempts", backend.writes)
	}
}

func TestSaveSurfacesReadErrors(t *testing.T) {
	sentinel := errors.New("vault is sealed")
	store := newTestStore(&fakeVault{readErr: sentinel})

	_, err := store.SaveRefreshed(context.Background(), testLocation, "example",
		&oauth2.Token{AccessToken: "at"})
	if !errors.Is(err, sentinel) {
		t.Fatalf("SaveRefreshed() error = %v, want the read error", err)
	}
}

func TestWithLockSerialisesCallers(t *testing.T) {
	store := newTestStore(&fakeVault{})

	var mu sync.Mutex
	var concurrent, maxConcurrent int
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = store.WithLock(testLocation, func() error {
				mu.Lock()
				concurrent++
				if concurrent > maxConcurrent {
					maxConcurrent = concurrent
				}
				mu.Unlock()

				time.Sleep(time.Millisecond)

				mu.Lock()
				concurrent--
				mu.Unlock()
				return nil
			})
		}()
	}
	wg.Wait()

	if maxConcurrent != 1 {
		t.Errorf("maxConcurrent = %d, want the location to be held exclusively", maxConcurrent)
	}
}

func TestWithLockAllowsDifferentLocationsInParallel(t *testing.T) {
	store := newTestStore(&fakeVault{})
	entered := make(chan struct{})
	release := make(chan struct{})

	go func() {
		_ = store.WithLock(Location{Mount: "secret", Path: "a"}, func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered

	done := make(chan struct{})
	go func() {
		_ = store.WithLock(Location{Mount: "secret", Path: "b"}, func() error { return nil })
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a lock on one location blocked another")
	}
	close(release)
}

func TestDecodeRecordRejectsBadTimestamp(t *testing.T) {
	_, err := decodeRecord(map[string]any{
		FieldAccessToken: "at",
		FieldExpiry:      "not-a-time",
	})
	if err == nil {
		t.Fatal("decodeRecord() error = nil, want a parse error")
	}
}

func TestDecodeRecordIgnoresUnknownFields(t *testing.T) {
	record, err := decodeRecord(map[string]any{
		FieldAccessToken: "at",
		"written_by":     "a newer version",
	})
	if err != nil {
		t.Fatalf("decodeRecord() error = %v", err)
	}
	if record.AccessToken != "at" {
		t.Errorf("AccessToken = %q, want at", record.AccessToken)
	}
	if !record.Expiry.IsZero() {
		t.Errorf("Expiry = %s, want zero when absent", record.Expiry)
	}
}

func TestLocationString(t *testing.T) {
	if got := testLocation.String(); got != "secret/oauth2/example" {
		t.Errorf("String() = %q, want secret/oauth2/example", got)
	}
}
