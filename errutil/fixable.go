package errutil

import "errors"

// To check whether an error is fixable (i.e., the user can change something in
// what they provided and to try again), use errutil.ErrIsFixable(err).
func ErrIsFixable(err error) bool {
	var fixableErr FixableError
	return errors.As(err, &fixableErr)
}

func Fixable(err error) error {
	return FixableError{Err: err}
}

type FixableError struct {
	Err error
}

func (f FixableError) Error() string {
	return f.Err.Error()
}
func (f FixableError) Unwrap() error {
	return f.Err
}
