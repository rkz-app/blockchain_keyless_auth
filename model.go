package auth

import "time"

type UserKey struct {
	ID            string `json:"id"`
	Address       string `json:"address"`
	Chain         string `json:"chain"`
	PublicKey     string `json:"public_key"`
	ExpiresAtSecs int64  `json:"expires_at_secs"`
}

func (u *UserKey) isExpired() bool {
	now := time.Now().Unix()
	return u.ExpiresAtSecs > now
}

type SignInput struct {
	IdToken   string
	PublicKey string
	Blinder   string
	ExpiresAt int64
	UidKey    string
}

type SignInOutput struct {
	token string
}
