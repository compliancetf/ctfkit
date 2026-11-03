package output

import "github.com/compliancetf/ctfkit/internal/validator"

// Formatter is the interface for all output formatters
type Formatter interface {
	Format(violations []validator.Violation) ([]byte, error)
}
