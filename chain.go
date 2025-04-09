package auth

import "context"

type Chain interface {
	GetName() string
	ExtractAddressFromSignInput(ctx context.Context, input *SignInput) (*string, error)
}
