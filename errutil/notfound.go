package errutil

import (
	"errors"
	"fmt"
)

func ErrIsNotFound(err error) bool {
	return errors.As(err, &NotFound{})
}

type NotFound struct {
	NameOrID string `json:"id"`
}

func (e NotFound) Error() string {
	return fmt.Sprintf("'%s' not found", e.NameOrID)
}
