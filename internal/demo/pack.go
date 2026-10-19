package demo

import (
	"fmt"
	"sort"
	"strings"

	"github.com/zysen1/Egress-Ledger/internal/gitpack"
)

// Pack builds a non-delta Git pack of files. Paths use forward slashes.
// The commit is fixed so the bytes do not depend on the clock or on the
// system Git version.
func Pack(files map[string][]byte) ([]byte, error) {
	root := &node{kids: map[string]*node{}}
	var paths []string
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		parts := strings.Split(path, "/")
		cur := root
		for i, part := range parts {
			if cur.kids == nil {
				cur.kids = map[string]*node{}
			}
			child, ok := cur.kids[part]
			if !ok {
				child = &node{name: part}
				cur.kids[part] = child
			}
			if i == len(parts)-1 {
				child.blob = files[path]
			} else if child.kids == nil {
				child.kids = map[string]*node{}
			}
			cur = child
		}
	}
	var objects []gitpack.Object
	var walk func(n *node) (string, error)
	walk = func(n *node) (string, error) {
		if n != root && n.blob != nil && len(n.kids) == 0 {
			obj := gitpack.Object{Type: gitpack.TypeBlob, Data: append([]byte(nil), n.blob...)}
			obj.Hash = gitpack.Hash(obj.Type, obj.Data)
			objects = append(objects, obj)
			return obj.Hash, nil
		}
		names := make([]string, 0, len(n.kids))
		for name := range n.kids {
			names = append(names, name)
		}
		sort.Strings(names)
		var entries []gitpack.TreeEntry
		for _, name := range names {
			child := n.kids[name]
			sum, err := walk(child)
			if err != nil {
				return "", err
			}
			mode := "100644"
			if len(child.kids) > 0 {
				mode = "40000"
			}
			entries = append(entries, gitpack.TreeEntry{Mode: mode, Name: name, Hash: sum})
		}
		data, err := gitpack.EncodeTree(entries)
		if err != nil {
			return "", err
		}
		obj := gitpack.Object{Type: gitpack.TypeTree, Data: data, Hash: gitpack.Hash(gitpack.TypeTree, data)}
		objects = append(objects, obj)
		return obj.Hash, nil
	}
	treeHash, err := walk(root)
	if err != nil {
		return nil, err
	}
	commit := fmt.Sprintf("tree %s\nauthor Egress Ledger Demo <demo@egressledger.local> 1700000000 +0000\ncommitter Egress Ledger Demo <demo@egressledger.local> 1700000000 +0000\n\nseed bait repo\n", treeHash)
	cobj := gitpack.Object{Type: gitpack.TypeCommit, Data: []byte(commit)}
	cobj.Hash = gitpack.Hash(cobj.Type, cobj.Data)
	objects = append(objects, cobj)
	return gitpack.Build(objects)
}

type node struct {
	name string
	blob []byte
	kids map[string]*node
}
