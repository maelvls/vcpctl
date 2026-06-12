package api

import "strings"

// LooksLikeAnID returns true if the string looks like a UUID (36 chars with 4 hyphens).
func LooksLikeAnID(s string) bool {
	if len(s) == 36 && strings.Count(s, "-") == 4 {
		return true
	}
	return false
}
