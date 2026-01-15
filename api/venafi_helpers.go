package api

import "strings"

func looksLikeAnID(s string) bool {
	if len(s) == 36 && strings.Count(s, "-") == 4 {
		return true
	}
	return false
}
