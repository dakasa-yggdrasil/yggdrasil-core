package runtime

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestDependencyShutdownHoldIsOptInAndPreservesOriginalError(t *testing.T) {
	original := errors.New("CI original join failure")
	for _, held := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary errors retain legacy continuation", true: "held original stops dependencies"}[held], func(t *testing.T) {
			app := New("ci")
			var order []string
			app.RegisterCloser(func(context.Context) error { order = append(order, "database"); return nil })
			app.RegisterCloser(func(context.Context) error { order = append(order, "broker"); return nil })
			app.RegisterCloser(func(context.Context) error {
				order = append(order, "original owner")
				if held {
					return errors.Join(original, ErrDependencyShutdownHeld)
				}
				return original
			})
			err := app.Shutdown(context.Background())
			if !errors.Is(err, original) || errors.Is(err, ErrDependencyShutdownHeld) != held {
				t.Fatal("original shutdown cause lost")
			}
			want := []string{"original owner", "broker", "database"}
			if held {
				want = want[:1]
			}
			if !reflect.DeepEqual(order, want) {
				t.Fatalf("wrong dependency order: %v", order)
			}
		})
	}
}
