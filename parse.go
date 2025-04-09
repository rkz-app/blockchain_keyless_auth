package auth

import (
	"github.com/techpro-studio/gohttplib/validator"
	"net/http"
)

func ParseInput(r *http.Request) (*SignInput, error) {
	const kIdToken = "id_token"
	const kPublicKey = "public_key"
	const kBlinder = "blinder"
	const kExpiresAt = "expires_at"
	const kUidKey = "uid_key"
	body, err := validator.GetValidatedBody(r, validator.VMap{
		kIdToken:   validator.RequiredStringValidators(kIdToken),
		kPublicKey: validator.RequiredStringValidators(kPublicKey),
		kBlinder:   validator.RequiredStringValidators(kBlinder),
		kExpiresAt: validator.RequiredFloatValidators(kExpiresAt),
		kUidKey:    validator.RequiredStringValidators(kUidKey),
	})
	if err != nil {
		return nil, err
	}
	expiresAt := int64(body[kExpiresAt].(float64))
	return &SignInput{
		IdToken:   body[kIdToken].(string),
		PublicKey: body[kPublicKey].(string),
		Blinder:   body[kBlinder].(string),
		ExpiresAt: expiresAt,
		UidKey:    body[kUidKey].(string),
	}, nil
}
