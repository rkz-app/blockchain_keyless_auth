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
	return u.ExpiresAtSecs < now
}

type SignInput struct {
	IdToken   string `json:"jwt_b64"`
	PublicKey string `json:"epk"`
	Blinder   string `json:"epk_blinder"`
	ExpiresAt int64  `json:"exp_date_secs"`
	UidKey    string `json:"uid_key"`
}

type SignInOutput struct {
	Token string `json:"token"`
}
