package config

// ValidClaim exposes an ecosystem's claim grammar to the external tests.
func ValidClaim(eco, c string) bool { return ecosystems[eco].validClaim(c) }
