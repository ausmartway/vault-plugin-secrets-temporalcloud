package temporalcloud

import (
	"context"
	"testing"
	"time"
)

func TestCredentialRequestContext(t *testing.T) {
	t.Run("caps a context with no deadline", func(t *testing.T) {
		started := time.Now()
		ctx, cancel := credentialRequestContext(context.Background())
		defer cancel()

		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("credential request context has no deadline")
		}
		got := deadline.Sub(started)
		if got < credentialRequestTimeout-time.Second || got > credentialRequestTimeout+time.Second {
			t.Fatalf("deadline is %s from start, want approximately %s", got, credentialRequestTimeout)
		}
	})

	t.Run("preserves a shorter parent deadline", func(t *testing.T) {
		parent, cancelParent := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelParent()
		parentDeadline, _ := parent.Deadline()

		ctx, cancel := credentialRequestContext(parent)
		defer cancel()
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("credential request context has no deadline")
		}
		if !deadline.Equal(parentDeadline) {
			t.Fatalf("deadline = %s, want parent deadline %s", deadline, parentDeadline)
		}
	})
}
