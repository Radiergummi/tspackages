package resolve

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"testing"
)

type src struct {
	name   string
	claims []string
}

func (s src) Name() string     { return s.name }
func (s src) Claims() []string { return s.claims }

func match(pattern, name string) bool {
	ok, _ := path.Match(pattern, name)
	return ok
}

func TestCandidatesClaimed(t *testing.T) {
	git := src{"git", []string{"matchory/*"}}
	pk := src{name: "packagist"}
	srcs := []src{git, pk}

	c, claimed := Candidates(srcs, "matchory/x", match)
	if !claimed || len(c) != 1 || c[0].name != "git" {
		t.Fatalf("got %v %v", c, claimed)
	}
	c, claimed = Candidates(srcs, "other/x", match)
	if claimed || len(c) != 1 || c[0].name != "packagist" {
		t.Fatalf("got %v %v", c, claimed)
	}
	c, claimed = Candidates([]src{git}, "other/x", match)
	if claimed || len(c) != 0 {
		t.Fatalf("got %v %v", c, claimed)
	}
}

func TestFirstNoFallThroughOnError(t *testing.T) {
	calls := 0
	_, _, err := First(context.Background(), []src{{name: "a"}, {name: "b"}}, func(_ context.Context, s src) (int, error) {
		calls++
		return 0, io.ErrUnexpectedEOF
	})
	var se *SourceError
	if !errors.As(err, &se) || se.Source != "a" || se.Timeout || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d", calls)
	}
}

func TestFirstNotFoundContinues(t *testing.T) {
	v, s, err := First(context.Background(), []src{{name: "a"}, {name: "b"}}, func(_ context.Context, s src) (int, error) {
		if s.name == "a" {
			return 0, ErrNotFound
		}
		return 7, nil
	})
	if err != nil || v != 7 || s.name != "b" {
		t.Fatalf("got %v %v %v", v, s, err)
	}
}

func TestFirstAllNotFound(t *testing.T) {
	_, _, err := First(context.Background(), []src{{name: "a"}}, func(context.Context, src) (int, error) {
		return 0, ErrNotFound
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	_, _, err = First(context.Background(), []src(nil), func(context.Context, src) (int, error) { return 0, nil })
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty: err = %v", err)
	}
}

func TestHTTPStatus(t *testing.T) {
	_, _, timeout := First(context.Background(), []src{{name: "a"}}, func(context.Context, src) (int, error) {
		return 0, context.DeadlineExceeded
	})
	_, _, other := First(context.Background(), []src{{name: "a"}}, func(context.Context, src) (int, error) {
		return 0, io.ErrUnexpectedEOF
	})
	for _, tt := range []struct {
		err  error
		want int
	}{{ErrNotFound, 404}, {other, 502}, {timeout, 504}} {
		if got := HTTPStatus(tt.err); got != tt.want {
			t.Errorf("%v: got %d want %d", tt.err, got, tt.want)
		}
	}
	if got := HTTPStatus(errors.New("x")); got != http.StatusInternalServerError {
		t.Errorf("unknown: %d", got)
	}
}

func firstErr(err error) error {
	_, _, e := First(context.Background(), []src{{name: "a"}, {name: "b"}}, func(_ context.Context, s src) (int, error) {
		if s.name == "a" {
			return 0, err
		}
		return 1, nil
	})
	return e
}

func TestFirstJoinedNotFoundIsSourceError(t *testing.T) {
	err := firstErr(errors.Join(io.ErrUnexpectedEOF, ErrNotFound))
	var se *SourceError
	if !errors.As(err, &se) || se.Source != "a" {
		t.Fatalf("err = %v", err)
	}
	if got := HTTPStatus(err); got != 502 {
		t.Fatalf("status = %d", got)
	}
	wrapped := fmt.Errorf("x: %w", errors.Join(io.ErrUnexpectedEOF, ErrNotFound))
	if !errors.As(firstErr(wrapped), &se) {
		t.Fatal("wrapped join fell through")
	}
}

func TestFirstWrappedNotFoundContinues(t *testing.T) {
	if err := firstErr(fmt.Errorf("x: %w", ErrNotFound)); err != nil {
		t.Fatalf("err = %v", err)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "t" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return false }

var _ net.Error = timeoutErr{}

func TestSourceErrorTimeouts(t *testing.T) {
	for name, in := range map[string]error{
		"os deadline":  os.ErrDeadlineExceeded,
		"wrapped os":   fmt.Errorf("x: %w", os.ErrDeadlineExceeded),
		"net timeout":  fmt.Errorf("x: %w", timeoutErr{}),
		"ctx deadline": fmt.Errorf("x: %w", context.DeadlineExceeded),
	} {
		var se *SourceError
		if !errors.As(firstErr(in), &se) || !se.Timeout || HTTPStatus(se) != 504 {
			t.Errorf("%s: not a timeout", name)
		}
	}
}

func TestHTTPStatusWrappedNotFound(t *testing.T) {
	if got := HTTPStatus(fmt.Errorf("x: %w", ErrNotFound)); got != 404 {
		t.Fatalf("got %d", got)
	}
}
