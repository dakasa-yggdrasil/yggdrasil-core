package capacitynativeqemu

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestExactOriginalCommand(t *testing.T) {
	vectors := []struct {
		Expected []string
		Actual   []string
	}{
		{[]string{"-uuid", "source-uuid", "-drive", "file=/source/root.qcow2,format=qcow2,if=virtio"},
			[]string{"qemu-system-x86_64", "-uuid", "source-uuid", "-drive", "file=/source/root.qcow2,format=qcow2,if=virtio"}},
	}
	// Optional cross-source vectors are generated from both real source trees;
	// no source path, credential, publication identity or native receipt is kept.
	if path := os.Getenv("ORIGINAL_QEMU_ARGV_VECTORS"); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(raw, &vectors); err != nil || len(vectors) != 2 {
			t.Fatal("two original slot vectors required", err)
		}
	}
	for _, v := range vectors {
		wire := func(args []string) []byte { return []byte(strings.Join(args, "\x00") + "\x00") }
		digest := func(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
		raw := wire(v.Actual)
		if !exactOriginalCommand(raw, v.Expected, digest(raw)) {
			t.Fatal("original argv rejected")
		}
		if exactOriginalCommand(raw, v.Expected, strings.Repeat("0", 64)) {
			t.Fatal("wrong original hash accepted")
		}
		for i := 1; i < len(v.Actual); i++ {
			changed := append([]string(nil), v.Actual...)
			changed[i] += "-changed"
			altered := wire(changed)
			if exactOriginalCommand(altered, v.Expected, digest(altered)) {
				t.Fatalf("changed argument %d accepted", i)
			}
		}
		for _, args := range [][]string{v.Actual[:len(v.Actual)-1], append(append([]string(nil), v.Actual...), "extra")} {
			altered := wire(args)
			if exactOriginalCommand(altered, v.Expected, digest(altered)) {
				t.Fatal("changed argument count accepted")
			}
		}
		old := []byte(strings.ReplaceAll(string(raw), ",if=virtio", ""))
		if exactOriginalCommand(old, v.Expected, digest(old)) {
			t.Fatal("implicit IDE accepted")
		}
	}
}
