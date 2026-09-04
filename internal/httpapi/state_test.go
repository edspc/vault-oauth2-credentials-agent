package httpapi

import (
	"testing"
	"time"
)

func TestStateStoreCreateAndConsume(t *testing.T) {
	now := baseTime
	store := newStateStore(10*time.Minute, func() time.Time { return now })

	state, err := store.Create("example", "verifier")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if len(state) < 32 {
		t.Errorf("len(state) = %d, want a long random value", len(state))
	}

	got, ok := store.Consume(state)
	if !ok {
		t.Fatal("Consume() = false, want the state to be found")
	}
	if got.EntryID != "example" || got.Verifier != "verifier" {
		t.Errorf("consumed = %+v, want example/verifier", got)
	}
	if _, ok := store.Consume(state); ok {
		t.Error("Consume() succeeded twice, want single use")
	}
}

func TestStateStoreRejectsEmptyAndUnknown(t *testing.T) {
	store := newStateStore(time.Minute, func() time.Time { return baseTime })
	if _, ok := store.Consume(""); ok {
		t.Error("Consume(\"\") = true, want false")
	}
	if _, ok := store.Consume("nope"); ok {
		t.Error("Consume(\"nope\") = true, want false")
	}
}

func TestStateStoreExpiresFlows(t *testing.T) {
	now := baseTime
	store := newStateStore(10*time.Minute, func() time.Time { return now })

	state, err := store.Create("example", "verifier")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	now = now.Add(11 * time.Minute)
	if _, ok := store.Consume(state); ok {
		t.Error("Consume() = true after the TTL elapsed, want false")
	}
	if store.Pending() != 0 {
		t.Errorf("Pending() = %d, want the expired flow purged", store.Pending())
	}
}

func TestStateStoreEvictsOldestWhenFull(t *testing.T) {
	now := baseTime
	store := newStateStore(time.Hour, func() time.Time { return now })

	first, err := store.Create("example", "")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	for range maxPendingStates {
		now = now.Add(time.Second)
		if _, err := store.Create("example", ""); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	if store.Pending() > maxPendingStates {
		t.Errorf("Pending() = %d, want it capped at %d", store.Pending(), maxPendingStates)
	}
	if _, ok := store.Consume(first); ok {
		t.Error("the oldest pending flow survived, want it evicted")
	}
}
