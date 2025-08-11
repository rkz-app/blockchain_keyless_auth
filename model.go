package auth

import "time"

type UserKey struct {
	ID                 string `json:"id"`
	Address            string `json:"address"`
	Chain              string `json:"chain"`
	PublicKey          string `json:"public_key,omitempty"`
	EphemeralPublicKey string `json:"ephemeral_public_key,omitempty"`
	DeviceId           string `json:"device_id"`
	ExpiresAtSecs      int64  `json:"expires_at_secs,omitempty"`
}

func (u *UserKey) GetSigningKey() string {
	if u.EphemeralPublicKey != "" {
		return u.EphemeralPublicKey
	}
	return u.PublicKey
}

func (u *UserKey) isExpired() bool {
	var zero int64
	if u.ExpiresAtSecs == zero {
		return false
	}
	now := time.Now().Unix()
	return u.ExpiresAtSecs < now
}

type SignInput struct {
	IdToken                   string `json:"jwt_b64"`
	EphemeralPublicKey        string `json:"epk"`
	DeviceId                  string `json:"device_id"`
	EphemeralPublicKeyBlinder string `json:"epk_blinder"`
	ExpiresAt                 int64  `json:"exp_date_secs"`
	UidKey                    string `json:"uid_key"`
}

type SignInOutput struct {
	Token string `json:"token"`
}

type AnonymousSignInput struct {
	Timestamp string `json:"timestamp"`
	DeviceId  string `json:"device_id"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`

	ExpiresAt                   int64  `json:"exp_date_secs,omitempty"`
	EphemeralPublicKey          string `json:"epk,omitempty"`
	EphemeralPublicKeySignature string `json:"epk_signature,omitempty"`
}
