package api

import (
	"fmt"
	"strings"

	"github.com/google/go-cmp/cmp"
)

func slicesEqual[T comparable](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func mapsEqual(a, b map[string]interface{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if a[k] != v {
			return false
		}
	}
	return true
}

// Without this, cmp.Diff would not be able to compare two
// 'ClientAuthenticationInformation' values as they contain the 'union' field,
// which is unexported and prevents comparison. Using this transformer changes a
// ClientAuthenticationInformation into one of the three concrete structs.
var transformClientAuthentication = cmp.Transformer("transformClientAuthentication", func(o ClientAuthenticationInformation) any {
	value, err := o.ValueByDiscriminator()
	if err != nil {
		return fmt.Sprintf("<error: %v>", err)
	}
	return value
})

func ANSIDiff(x, y any, opts ...cmp.Option) string {
	escapeCode := func(code int) string {
		return fmt.Sprintf("\x1b[%dm", code)
	}

	opts = append(opts, transformClientAuthentication)
	diff := cmp.Diff(x, y, opts...)
	if diff == "" {
		return ""
	}

	ss := strings.Split(diff, "\n")
	for i, s := range ss {
		switch {
		case strings.HasPrefix(s, "-"):
			ss[i] = escapeCode(31) + s + escapeCode(0)
		case strings.HasPrefix(s, "+"):
			ss[i] = escapeCode(32) + s + escapeCode(0)
		}
	}
	return strings.Join(ss, "\n")
}
