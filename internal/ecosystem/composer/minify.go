package composer

// Expand is Composer's MetadataMinifier::expand: every entry inherits the
// previous expanded entry's keys, and the value "__unset" removes a key. The
// input is not modified and no nested value is shared between entries.
func Expand(versions []map[string]any) []map[string]any {
	out := make([]map[string]any, 0, len(versions))
	var prev map[string]any
	for _, v := range versions {
		cur := make(map[string]any, len(prev)+len(v))
		for k, v := range prev {
			cur[k] = cloneValue(v)
		}
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

func cloneValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, e := range t {
			m[k] = cloneValue(e)
		}
		return m
	case []any:
		l := make([]any, len(t))
		for i, e := range t {
			l[i] = cloneValue(e)
		}
		return l
	}
	return v
}
