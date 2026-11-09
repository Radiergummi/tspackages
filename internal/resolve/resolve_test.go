package resolve

import (
	"context"
	"errors"
	"io"
	"net/http"
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
