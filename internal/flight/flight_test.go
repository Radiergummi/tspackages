package flight

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/sync/singleflight"
)

func TestFlightFollowerStopsWaitingOnItsOwnCancel(t *testing.T) {
	var g singleflight.Group
	release := make(chan struct{})
	defer close(release)
	started := make(chan struct{})
	go Do(context.Background(), &g, "k", func() (int, error) {
		close(started)
		<-release
		return 1, nil
	})
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := Do(ctx, &g, "k", func() (int, error) { return 2, nil })
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("follower kept waiting for the leader")
	}
}
