package plugins

// Unique returns items with duplicates removed, preserving the order of first
// occurrence. Plugins accumulating findings across paginated responses should
// use this rather than threading an inline `seen` map through the loop.
func Unique[T comparable](items []T) []T {
	return UniqueBy(items, func(item T) T { return item })
}

// UniqueBy is Unique for values that are not themselves comparable, or that
// should be deduplicated on one field. The FIRST item for a given key wins, so
// sorting beforehand chooses which duplicate survives — e.g. sorting
// most-recent-first keeps the freshest record for each domain.
func UniqueBy[T any, K comparable](items []T, key func(T) K) []T {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[K]struct{}, len(items))
	out := make([]T, 0, len(items))
	for _, item := range items {
		k := key(item)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, item)
	}
	return out
}
