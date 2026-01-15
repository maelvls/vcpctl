package errutil

import "fmt"

type NotFound struct {
	NameOrID string `json:"id"`
}

func (e NotFound) Error() string {
	return fmt.Sprintf("'%s' not found", e.NameOrID)
}
