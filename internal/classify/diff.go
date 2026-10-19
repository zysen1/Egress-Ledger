package classify

import "sort"

// Diff is the change in observed egress between two versions.
type Diff struct {
	OldVersion       string          `json:"old_version"`
	NewVersion       string          `json:"new_version"`
	DomainsAdded     []string        `json:"domains_added"`
	DomainsRemoved   []string        `json:"domains_removed"`
	Categories       []CategoryDelta `json:"categories"`
	SecretsAdded     []SecretHit     `json:"secrets_added"`
	SecretsRemoved   []SecretHit     `json:"secrets_removed"`
	FilesAdded       []FileHit       `json:"files_added"`
	FilesRemoved     []FileHit       `json:"files_removed"`
	GitAdded         []GitHit        `json:"git_added"`
	GitRemoved       []GitHit        `json:"git_removed"`
	InvisibleAdded   []Invisible     `json:"invisible_added"`
	InvisibleRemoved []Invisible     `json:"invisible_removed"`
}

// CategoryDelta is one category's body-byte change.
type CategoryDelta struct {
	Name  string `json:"name"`
	Old   int    `json:"old_body_bytes"`
	New   int    `json:"new_body_bytes"`
	Delta int    `json:"delta_body_bytes"`
}

// Compare reports what new sent that old did not, and the reverse.
func Compare(old, new *Report) *Diff {
	d := &Diff{OldVersion: old.Version, NewVersion: new.Version}
	oldHosts := map[string]bool{}
	newHosts := map[string]bool{}
	for _, h := range old.Domains {
		oldHosts[h.Host] = true
	}
	for _, h := range new.Domains {
		newHosts[h.Host] = true
	}
	for h := range newHosts {
		if !oldHosts[h] {
			d.DomainsAdded = append(d.DomainsAdded, h)
		}
	}
	for h := range oldHosts {
		if !newHosts[h] {
			d.DomainsRemoved = append(d.DomainsRemoved, h)
		}
	}
	sort.Strings(d.DomainsAdded)
	sort.Strings(d.DomainsRemoved)
	oldCat := map[string]int{}
	newCat := map[string]int{}
	for _, c := range old.Categories {
		oldCat[c.Name] = c.BodyBytes
	}
	for _, c := range new.Categories {
		newCat[c.Name] = c.BodyBytes
	}
	for _, name := range Categories {
		o, n := oldCat[name], newCat[name]
		d.Categories = append(d.Categories, CategoryDelta{Name: name, Old: o, New: n, Delta: n - o})
	}
	d.SecretsAdded, d.SecretsRemoved = diffBy(old.Secrets, new.Secrets, secretKey)
	d.FilesAdded, d.FilesRemoved = diffBy(old.Files, new.Files, fileKey)
	d.GitAdded, d.GitRemoved = diffBy(old.Git, new.Git, gitKey)
	d.InvisibleAdded, d.InvisibleRemoved = diffBy(old.Invisible, new.Invisible, invisibleKey)
	sort.Slice(d.SecretsAdded, func(i, j int) bool { return secretKey(d.SecretsAdded[i]) < secretKey(d.SecretsAdded[j]) })
	sort.Slice(d.SecretsRemoved, func(i, j int) bool { return secretKey(d.SecretsRemoved[i]) < secretKey(d.SecretsRemoved[j]) })
	sort.Slice(d.FilesAdded, func(i, j int) bool { return fileKey(d.FilesAdded[i]) < fileKey(d.FilesAdded[j]) })
	sort.Slice(d.FilesRemoved, func(i, j int) bool { return fileKey(d.FilesRemoved[i]) < fileKey(d.FilesRemoved[j]) })
	sort.Slice(d.GitAdded, func(i, j int) bool { return gitKey(d.GitAdded[i]) < gitKey(d.GitAdded[j]) })
	sort.Slice(d.GitRemoved, func(i, j int) bool { return gitKey(d.GitRemoved[i]) < gitKey(d.GitRemoved[j]) })
	sort.Slice(d.InvisibleAdded, func(i, j int) bool { return invisibleKey(d.InvisibleAdded[i]) < invisibleKey(d.InvisibleAdded[j]) })
	sort.Slice(d.InvisibleRemoved, func(i, j int) bool { return invisibleKey(d.InvisibleRemoved[i]) < invisibleKey(d.InvisibleRemoved[j]) })
	return d
}

func diffBy[T any](old, new []T, key func(T) string) (added, removed []T) {
	om := map[string]T{}
	nm := map[string]T{}
	for _, item := range old {
		om[key(item)] = item
	}
	for _, item := range new {
		nm[key(item)] = item
	}
	for k, item := range nm {
		if _, ok := om[k]; !ok {
			added = append(added, item)
		}
	}
	for k, item := range om {
		if _, ok := nm[k]; !ok {
			removed = append(removed, item)
		}
	}
	return added, removed
}

func secretKey(s SecretHit) string {
	return s.Pattern + "\x00" + s.Host + "\x00" + s.Source + "\x00" + s.Object + "\x00" + s.Redacted
}

func fileKey(f FileHit) string {
	return f.Rel + "\x00" + f.Host + "\x00" + f.Source
}

func gitKey(g GitHit) string {
	return g.Host + "\x00" + g.Kind + "\x00" + g.Object + "\x00" + g.Hash
}

func invisibleKey(i Invisible) string {
	return i.Host + "\x00" + i.Reason
}
