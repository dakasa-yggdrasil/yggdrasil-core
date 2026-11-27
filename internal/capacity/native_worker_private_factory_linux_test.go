//go:build linux

package capacity

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestNativePrivateFactoryProtectedFileReadRefusesAliasesAndUnsafeModes(t *testing.T) {
	for _, mode := range []string{"owned-private", "world-readable", "group-writable", "symlink", "hardlink", "empty", "oversized", "relative"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "dedicated-agent-material")
			want := bytes.Repeat([]byte{7}, 32)
			if mode == "empty" {
				want = nil
			}
			if mode == "oversized" {
				want = append(want, 1)
			}
			if e := os.WriteFile(path, want, 0600); e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "world-readable":
				if e := os.Chmod(path, 0644); e != nil {
					t.Fatal(e)
				}
			case "group-writable":
				if e := os.Chmod(path, 0620); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				alias := path + "-alias"
				if e := os.Symlink(path, alias); e != nil {
					t.Fatal(e)
				}
				path = alias
			case "hardlink":
				if e := os.Link(path, path+"-alias"); e != nil {
					t.Fatal(e)
				}
			case "relative":
				path = "relative-private-material"
			}
			got, e := nativePrivateReadFile(path, 32, true)
			if mode == "owned-private" {
				if e != nil || !bytes.Equal(got, want) {
					t.Fatal("protected material refused", e)
				}
				nativePrivateWipe(got)
			} else if e == nil || len(got) != 0 {
				t.Fatal("unqualified private material accepted", mode)
			}
		})
	}
}

func TestNativePrivateFactoryRejectsCAFilesContainingNonCertificateMaterial(t *testing.T) {
	f, _ := nativePrivateFactoryFixture(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	defer f.Close()
	if !nativePrivateCAPEM(f.ca) {
		t.Fatal("synthetic root CA refused")
	}
	for _, raw := range [][]byte{append([]byte("private-prefix\n"), f.ca...), append(append([]byte{}, f.ca...), []byte("-----BEGIN PRIVATE KEY-----\nAQ==\n-----END PRIVATE KEY-----\n")...), []byte("not-a-certificate")} {
		if nativePrivateCAPEM(raw) {
			t.Fatal("private key or noncertificate bytes accepted as public CA")
		}
	}
}

func TestNativePrivateFactoryCleansExitedParentsClosedFDDescendant(t *testing.T) {
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "original-owned-group")
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
	script := "#!/bin/sh\n/usr/bin/sleep 60 </dev/null >/dev/null 2>/dev/null 3>&- 4>&- &\nchild=$!\nprintf '%s %s\\n' \"$$\" \"$child\" > " + quote(pidPath) + "\nprintf '#cloud-config\\nfixture: owned-child-cleanup\\n' >&3\nexit 0\n"
	helper := filepath.Join(dir, "negative-cleanup-helper")
	if e := os.WriteFile(helper, []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(helper)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	body, runErr := nativePrivateRunPinned(ctx, f, []byte{}, time.Now().Add(5*time.Second))
	defer nativePrivateWipe(body)
	ids, e := os.ReadFile(pidPath)
	if e != nil {
		t.Fatal("negative helper did not record original ownership", e)
	}
	parts := strings.Fields(string(ids))
	if len(parts) != 2 {
		t.Fatal("negative helper ownership incomplete")
	}
	parent, e1 := strconv.Atoi(parts[0])
	child, e2 := strconv.Atoi(parts[1])
	if e1 != nil || e2 != nil || parent < 1 || child < 1 {
		t.Fatal("negative helper ownership invalid")
	}
	defer func() {
		if group, e := syscall.Getpgid(child); e == nil && group == parent {
			_ = syscall.Kill(-parent, syscall.SIGKILL)
		}
	}()
	if runErr != nil || len(body) == 0 || syscall.Kill(-parent, 0) != syscall.ESRCH || syscall.Kill(child, 0) != syscall.ESRCH {
		t.Fatal("original parent/group or closed-FD descendant survived cleanup", runErr)
	}
}

func TestNativePrivateFactoryHostRunnerHasOnlyTheVerifiedProductionEntry(t *testing.T) {
	paths, e := filepath.Glob("native_worker_private_factory*.go")
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, e := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if e != nil {
			t.Fatal(e)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				name, ok := call.Fun.(*ast.Ident)
				if !ok || name.Name != "nativePrivateRunPinned" {
					return true
				}
				calls++
				if fn.Name.Name != "nativePrivateExecute" || len(fn.Body.List) != 2 {
					t.Error("host runner bypasses the fixed verified entry")
				}
				return true
			})
		}
	}
	if calls != 1 {
		t.Fatalf("expected one fixed production runner entry, got %d", calls)
	}
}
