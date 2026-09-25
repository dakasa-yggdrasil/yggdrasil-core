package httpapi

import (
	"os"
	"testing"
)

// TestMain gives the package the explicit development environment ADR-0022
// requires for the credential-free machine posture. Most tests here exercise
// a Server with no machine credential configured and rely on that posture;
// before ADR-0022 an unset YGGDRASIL_ENV granted it. A value the runner
// already sets is kept, and every test that asserts the closed posture sets
// or unsets YGGDRASIL_ENV itself.
func TestMain(m *testing.M) {
	if _, present := os.LookupEnv("YGGDRASIL_ENV"); !present {
		if err := os.Setenv("YGGDRASIL_ENV", "test"); err != nil {
			panic(err)
		}
	}
	os.Exit(m.Run())
}
