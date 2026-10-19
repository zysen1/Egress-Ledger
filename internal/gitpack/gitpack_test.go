package gitpack

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	blob := Object{Type: TypeBlob, Data: []byte("hello pack\n")}
	blob.Hash = Hash(TypeBlob, blob.Data)
	treeData, err := EncodeTree([]TreeEntry{{Mode: "100644", Name: "hello.txt", Hash: blob.Hash}})
	if err != nil {
		t.Fatal(err)
	}
	tree := Object{Type: TypeTree, Data: treeData, Hash: Hash(TypeTree, treeData)}
	commitBody := []byte("tree " + tree.Hash + "\n\nseed\n")
	commit := Object{Type: TypeCommit, Data: commitBody, Hash: Hash(TypeCommit, commitBody)}
	pack, err := Build([]Object{blob, tree, commit})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(pack)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.ChecksumOK {
		t.Fatal("checksum")
	}
	if len(parsed.Objects) != 3 {
		t.Fatalf("objects: %d", len(parsed.Objects))
	}
	if parsed.Paths[blob.Hash] != "hello.txt" {
		t.Fatalf("path: %q", parsed.Paths[blob.Hash])
	}
	if parsed.Objects[0].Type != TypeBlob || !bytes.Equal(parsed.Objects[0].Data, blob.Data) {
		t.Fatalf("blob mismatch %+v", parsed.Objects[0])
	}
}

func TestRejectsPackageWord(t *testing.T) {
	_, err := Parse([]byte("PACKAGE is not a packfile"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestMatchesGitHashObject(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	blob := []byte("hello pack\n")
	if got := gitHash(t, TypeBlob, blob); got != Hash(TypeBlob, blob) {
		t.Fatalf("blob hash git %s ours %s", got, Hash(TypeBlob, blob))
	}
	tree, err := EncodeTree([]TreeEntry{{Mode: "100644", Name: "hello.txt", Hash: Hash(TypeBlob, blob)}})
	if err != nil {
		t.Fatal(err)
	}
	if got := gitHash(t, TypeTree, tree); got != Hash(TypeTree, tree) {
		t.Fatalf("tree hash git %s ours %s", got, Hash(TypeTree, tree))
	}
}

func gitHash(t *testing.T, kind string, data []byte) string {
	t.Helper()
	cmd := exec.Command("git", "hash-object", "-t", kind, "--stdin")
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func TestBadChecksum(t *testing.T) {
	blob := Object{Type: TypeBlob, Data: bytes.Repeat([]byte("a"), 40)}
	blob.Hash = Hash(TypeBlob, blob.Data)
	pack, err := Build([]Object{blob})
	if err != nil {
		t.Fatal(err)
	}
	pack[len(pack)-1] ^= 0xff
	parsed, err := Parse(pack)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ChecksumOK {
		t.Fatal("expected bad checksum")
	}
}
