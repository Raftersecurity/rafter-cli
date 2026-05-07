package eventbus

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestPublishFanout(t *testing.T) {
	b := New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c1, _ := b.Subscribe(ctx)
	c2, _ := b.Subscribe(ctx)
	if got := b.SubscriberCount(); got != 2 {
		t.Fatalf("SubscriberCount = %d, want 2", got)
	}

	want := Event{Type: EventScanStarted}
	b.Publish(want)

	for i, ch := range []<-chan Event{c1, c2} {
		select {
		case got := <-ch:
			if got.Type != want.Type {
				t.Errorf("sub %d: Type = %q, want %q", i, got.Type, want.Type)
			}
			if got.Timestamp.IsZero() {
				t.Errorf("sub %d: Timestamp not auto-stamped", i)
			}
		case <-time.After(time.Second):
			t.Fatalf("sub %d: did not receive event", i)
		}
	}
}

func TestSubscribePreservesCallerTimestamp(t *testing.T) {
	b := New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, _ := b.Subscribe(ctx)

	stamp := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	b.Publish(Event{Type: EventSecretCreated, Timestamp: stamp})

	select {
	case got := <-ch:
		if !got.Timestamp.Equal(stamp) {
			t.Errorf("Timestamp = %v, want %v", got.Timestamp, stamp)
		}
	case <-time.After(time.Second):
		t.Fatal("no event received")
	}
}

func TestUnsubscribeOnContextCancel(t *testing.T) {
	b := New()
	ctx, cancel := context.WithCancel(context.Background())
	ch, _ := b.Subscribe(ctx)
	if got := b.SubscriberCount(); got != 1 {
		t.Fatalf("SubscriberCount = %d, want 1", got)
	}

	cancel()
	// Wait for the cleanup goroutine to remove the subscription.
	deadline := time.Now().Add(time.Second)
	for b.SubscriberCount() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("subscriber not removed after cancel")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Receive should now drain the closed channel.
	if _, ok := <-ch; ok {
		t.Error("channel should be closed after cancel")
	}
}

func TestSlowSubscriberDoesNotBlockPublisher(t *testing.T) {
	b := New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, h := b.Subscribe(ctx)

	// Publish more than the buffer can hold; the subscriber never reads.
	const overflow = subscriberBufferSize + 8
	done := make(chan struct{})
	go func() {
		for i := 0; i < overflow; i++ {
			b.Publish(Event{Type: EventScanStarted})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a full subscriber")
	}
	if got := h.DroppedEvents(); got == 0 {
		t.Errorf("expected drops > 0 for overflow, got %d", got)
	}
}

func TestPublishConcurrent(t *testing.T) {
	b := New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, _ := b.Subscribe(ctx)

	const n = 32
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			b.Publish(Event{Type: EventScanStarted})
		}()
	}
	wg.Wait()

	got := 0
	deadline := time.After(time.Second)
loop:
	for got < n {
		select {
		case <-ch:
			got++
		case <-deadline:
			break loop
		}
	}
	if got != n {
		t.Errorf("received %d events, want %d", got, n)
	}
}
