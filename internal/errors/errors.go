package errors

import (
	"errors"
	"fmt"
)

var (
	ErrNotImplemented = errors.New("not implemented")
	ErrZoneNotFound   = errors.New("zone not found")
	ErrInvalidFQDN    = errors.New("invalid FQDN")
	ErrCacheMissing   = errors.New("zones cache missing")
)

func NotImplemented(name string) error {
	return fmt.Errorf("%w: %s", ErrNotImplemented, name)
}
