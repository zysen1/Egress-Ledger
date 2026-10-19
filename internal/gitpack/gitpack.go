// Package gitpack builds and reads non-delta Git packfiles.
// Object bytes are the raw commit, tree, or blob contents (not the
// loose-object envelope). Hashes follow the Git object-id rule.
package gitpack

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
)

const (
	TypeCommit = "commit"
	TypeTree   = "tree"
	TypeBlob   = "blob"
	TypeTag    = "tag"
	TypeDelta  = "delta"
)

// Object is one pack entry.
type Object struct {
	Type string
	Data []byte
	Hash string // hex sha1
}

// TreeEntry is one line of a Git tree.
type TreeEntry struct {
	Mode string
	Name string
	Hash string // hex
}

// Hash computes the Git object id of kind and data.
func Hash(kind string, data []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "%s %d\x00", kind, len(data))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// EncodeTree serializes entries in Git's tree order.
func EncodeTree(entries []TreeEntry) ([]byte, error) {
	sorted := append([]TreeEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool {
		return treeSortKey(sorted[i]) < treeSortKey(sorted[j])
	})
	var buf bytes.Buffer
	for _, e := range sorted {
		raw, err := hex.DecodeString(e.Hash)
		if err != nil || len(raw) != 20 {
			return nil, fmt.Errorf("gitpack: bad tree hash for %s", e.Name)
		}
		fmt.Fprintf(&buf, "%s %s\x00", e.Mode, e.Name)
		buf.Write(raw)
	}
	return buf.Bytes(), nil
}

func treeSortKey(e TreeEntry) string {
	if e.Mode == "40000" || e.Mode == "040000" {
		return e.Name + "/"
	}
	return e.Name
}

// ParseTree reads a tree object.
func ParseTree(data []byte) ([]TreeEntry, error) {
	var out []TreeEntry
	for len(data) > 0 {
		sp := bytes.IndexByte(data, ' ')
		if sp <= 0 {
			return nil, errors.New("gitpack: bad tree mode")
		}
		mode := string(data[:sp])
		rest := data[sp+1:]
		nul := bytes.IndexByte(rest, 0)
		if nul < 0 || len(rest) < nul+1+20 {
			return nil, errors.New("gitpack: bad tree entry")
		}
		name := string(rest[:nul])
		var sum [20]byte
		copy(sum[:], rest[nul+1:nul+21])
		out = append(out, TreeEntry{Mode: mode, Name: name, Hash: hex.EncodeToString(sum[:])})
		data = rest[nul+21:]
	}
	return out, nil
}

// Build writes a version-2 pack. Checksum covers every preceding byte.
func Build(objects []Object) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("PACK")
	if err := binary.Write(&buf, binary.BigEndian, uint32(2)); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(objects))); err != nil {
		return nil, err
	}
	for _, o := range objects {
		code, ok := typeCode(o.Type)
		if !ok {
			return nil, fmt.Errorf("gitpack: unknown type %s", o.Type)
		}
		buf.Write(encodeSize(code, len(o.Data)))
		var z bytes.Buffer
		w := zlib.NewWriter(&z)
		if _, err := w.Write(o.Data); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
		buf.Write(z.Bytes())
	}
	sum := sha1.Sum(buf.Bytes())
	buf.Write(sum[:])
	return buf.Bytes(), nil
}

// Pack is a parsed packfile.
type Pack struct {
	Objects    []Object
	ChecksumOK bool
	// Paths maps a blob or tree hash to a repo-relative path when trees
	// in the same pack name it. The root tree has path "".
	Paths map[string]string
}

// Parse finds a PACK header in b and walks objects. A pkt-line prefix is allowed.
func Parse(b []byte) (*Pack, error) {
	idx := bytes.Index(b, []byte("PACK"))
	if idx < 0 {
		return nil, errors.New("gitpack: no PACK header")
	}
	b = b[idx:]
	if len(b) < 12+20 {
		return nil, errors.New("gitpack: short pack")
	}
	if !bytes.Equal(b[:4], []byte("PACK")) {
		return nil, errors.New("gitpack: bad magic")
	}
	version := binary.BigEndian.Uint32(b[4:8])
	if version != 2 && version != 3 {
		return nil, fmt.Errorf("gitpack: unsupported version %d", version)
	}
	count := binary.BigEndian.Uint32(b[8:12])
	if count > 5_000_000 {
		return nil, errors.New("gitpack: implausible object count")
	}
	pos := 12
	objs := make([]Object, 0, count)
	for i := uint32(0); i < count; i++ {
		if pos >= len(b)-20 {
			return nil, errors.New("gitpack: truncated object header")
		}
		code, size, n, err := decodeSize(b[pos:])
		if err != nil {
			return nil, err
		}
		pos += n
		kind := typeName(code)
		if kind == TypeDelta {
			advance, err := skipDeltaHeader(code, b[pos:])
			if err != nil {
				return nil, err
			}
			pos += advance
		}
		// bytes.Reader implements io.ByteReader, so zlib/flate read exactly
		// the compressed stream instead of buffering past it.
		br := bytes.NewReader(b[pos:])
		zr, err := zlib.NewReader(br)
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(zr)
		zr.Close()
		if err != nil {
			return nil, err
		}
		consumed := int(br.Size()) - br.Len()
		if consumed <= 0 {
			return nil, errors.New("gitpack: zlib size")
		}
		pos += consumed
		if size != len(data) {
			return nil, fmt.Errorf("gitpack: size mismatch for %s: header %d inflated %d", kind, size, len(data))
		}
		obj := Object{Type: kind, Data: data}
		if kind != TypeDelta {
			obj.Hash = Hash(kind, data)
		}
		objs = append(objs, obj)
	}
	if len(b) < pos+20 {
		return nil, errors.New("gitpack: missing checksum")
	}
	sum := sha1.Sum(b[:pos])
	ok := bytes.Equal(sum[:], b[pos:pos+20])
	p := &Pack{Objects: objs, ChecksumOK: ok, Paths: map[string]string{}}
	p.indexPaths()
	return p, nil
}

func (p *Pack) indexPaths() {
	byHash := map[string]Object{}
	for _, o := range p.Objects {
		if o.Hash != "" {
			byHash[o.Hash] = o
		}
	}
	var roots []Object
	referenced := map[string]bool{}
	for _, o := range p.Objects {
		if o.Type != TypeTree {
			continue
		}
		entries, err := ParseTree(o.Data)
		if err != nil {
			continue
		}
		for _, e := range entries {
			referenced[e.Hash] = true
		}
	}
	for _, o := range p.Objects {
		if o.Type == TypeTree && !referenced[o.Hash] {
			roots = append(roots, o)
		}
	}
	var walk func(hash, prefix string)
	walk = func(hash, prefix string) {
		o, ok := byHash[hash]
		if !ok || o.Type != TypeTree {
			return
		}
		if prefix == "" {
			p.Paths[hash] = ""
		}
		entries, err := ParseTree(o.Data)
		if err != nil {
			return
		}
		for _, e := range entries {
			name := e.Name
			if prefix != "" {
				name = prefix + "/" + e.Name
			}
			p.Paths[e.Hash] = name
			if e.Mode == "40000" || e.Mode == "040000" {
				walk(e.Hash, name)
			}
		}
	}
	for _, r := range roots {
		walk(r.Hash, "")
	}
}

func skipDeltaHeader(code int, b []byte) (int, error) {
	if code == 7 {
		if len(b) < 20 {
			return 0, errors.New("gitpack: short ref delta")
		}
		return 20, nil
	}
	// ofs-delta
	if len(b) == 0 {
		return 0, errors.New("gitpack: short ofs delta")
	}
	i := 0
	c := b[i]
	i++
	for c&0x80 != 0 {
		if i >= len(b) {
			return 0, errors.New("gitpack: short ofs delta")
		}
		c = b[i]
		i++
	}
	return i, nil
}

func encodeSize(typeCode, size int) []byte {
	var out []byte
	b := byte((typeCode << 4) | (size & 0x0f))
	size >>= 4
	if size > 0 {
		b |= 0x80
	}
	out = append(out, b)
	for size > 0 {
		c := byte(size & 0x7f)
		size >>= 7
		if size > 0 {
			c |= 0x80
		}
		out = append(out, c)
	}
	return out
}

func decodeSize(b []byte) (typeCode, size, n int, err error) {
	if len(b) == 0 {
		return 0, 0, 0, errors.New("gitpack: empty size")
	}
	c := b[0]
	typeCode = int((c >> 4) & 7)
	size = int(c & 0x0f)
	n = 1
	shift := 4
	for c&0x80 != 0 {
		if n >= len(b) {
			return 0, 0, 0, errors.New("gitpack: truncated size")
		}
		c = b[n]
		n++
		size |= int(c&0x7f) << shift
		shift += 7
	}
	return typeCode, size, n, nil
}

func typeCode(name string) (int, bool) {
	switch name {
	case TypeCommit:
		return 1, true
	case TypeTree:
		return 2, true
	case TypeBlob:
		return 3, true
	case TypeTag:
		return 4, true
	default:
		return 0, false
	}
}

func typeName(code int) string {
	switch code {
	case 1:
		return TypeCommit
	case 2:
		return TypeTree
	case 3:
		return TypeBlob
	case 4:
		return TypeTag
	case 6, 7:
		return TypeDelta
	default:
		return fmt.Sprintf("unknown-%d", code)
	}
}
