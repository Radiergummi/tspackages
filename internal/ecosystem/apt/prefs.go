package apt

import (
	"strings"
)

// RenderPreferences returns the apt preferences file for the storage sources
// in config order: each source's claimed names are pinned to its release and
// removed from every other.
func RenderPreferences(storage []Uploader) []byte {
	var b strings.Builder
	for i, s := range storage {
		if i > 0 {
			b.WriteByte('\n')
		}
		pkgs := "Package: " + strings.Join(s.Claims(), " ") + "\n"
		b.WriteString(pkgs + "Pin: release o=tspackages,l=" + s.Name() + "\nPin-Priority: 1001\n\n")
		b.WriteString(pkgs + "Pin: release *\nPin-Priority: -1\n")
	}
	return []byte(b.String())
}
