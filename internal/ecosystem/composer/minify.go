package composer

import "maps"

// Expand is Composer's MetadataMinifier::expand: every entry inherits the
// previous expanded entry's keys, and the value "__unset" removes a key. The
// input is not modified; values are shared, not deep-copied.
func Expand(versions []map[string]any) []map[string]any {
	out := make([]map[string]any, 0, len(versions))
	var prev map[string]any
	for _, v := range versions {
		cur := make(map[string]any, len(prev)+len(v))
		maps.Copy(cur, prev)
		for k, val := range v {
			if s, ok := val.(string); ok && s == "__unset" {
				delete(cur, k)
				continue
			}
			cur[k] = val
		}
		out = append(out, cur)
		prev = cur
	}
	return out
}
