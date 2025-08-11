package auth

import "context"

type Repository interface {
	GetUserKey(ctx context.Context, userKeyId string) (*UserKey, error)
	CreateUserKey(ctx context.Context, publicKey, ephemeralPublicKey, chain, address, deviceId string, expiresAtSecs int64) (*UserKey, error)
	GetUserKeys(ctx context.Context, address string) ([]*UserKey, error)
	DeleteUserKey(ctx context.Context, userKeyId string) error
	DeleteUserKeys(ctx context.Context, address string) error
}
