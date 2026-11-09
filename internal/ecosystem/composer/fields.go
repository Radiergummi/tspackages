package composer

// publishable is the composer.json keys a hosted source may serve. Everything
// else (source, dist, notification-url, transport-options, scripts, ...) could
// redirect or influence clients and is dropped.
var publishable = map[string]bool{
	"name": true, "description": true, "type": true, "keywords": true,
	"homepage": true, "readme": true, "time": true, "license": true,
	"authors": true, "support": true, "funding": true, "require": true,
	"require-dev": true, "conflict": true, "replace": true, "provide": true,
	"suggest": true, "autoload": true, "autoload-dev": true,
	"include-path": true, "target-dir": true, "extra": true, "bin": true,
	"archive": true, "abandoned": true, "non-feature-branches": true,
}

// PublishableFields returns a copy of composerJSON restricted to the
// allowlisted keys (values are shared, not deep-copied).
func PublishableFields(composerJSON map[string]any) map[string]any {
	out := make(map[string]any, len(composerJSON))
	for k, v := range composerJSON {
		if publishable[k] {
			out[k] = v
		}
	}
	return out
}
