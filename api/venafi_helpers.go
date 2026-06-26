package api

import (
	"github.com/google/uuid"
)

// LooksLikeAnID returns true if the string is a valid UUID.
func LooksLikeAnID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}
