package auth

import (
	"net/http"

	"github.com/techpro-studio/gohttplib"
	"github.com/techpro-studio/gohttplib/validator"
)

func ParseInput(r *http.Request) (*SignInput, error) {
	const kIdToken = "id_token"
	const kPublicKey = "public_key"
	const kBlinder = "blinder"
	const kExpiresAt = "expires_at"
	const kDeviceId = "device_id"
	const kUidKey = "uid_key"
	body, err := validator.GetValidatedBody(r, validator.VMap{
		kIdToken:   validator.RequiredStringValidators(kIdToken),
		kPublicKey: validator.RequiredStringValidators(kPublicKey),
		kBlinder:   validator.RequiredStringValidators(kBlinder),
		kExpiresAt: validator.RequiredFloatValidators(kExpiresAt),
		kUidKey:    validator.RequiredStringValidators(kUidKey),
		kDeviceId:  validator.RequiredStringValidators(kDeviceId),
	})
	if err != nil {
		return nil, err
	}
	expiresAt := int64(body[kExpiresAt].(float64))
	return &SignInput{
		IdToken:                   body[kIdToken].(string),
		EphemeralPublicKey:        body[kPublicKey].(string),
		DeviceId:                  body[kDeviceId].(string),
		EphemeralPublicKeyBlinder: body[kBlinder].(string),
		ExpiresAt:                 expiresAt,
		UidKey:                    body[kUidKey].(string),
	}, nil
}

func ParseAnonymousInput(r *http.Request) (*AnonymousSignInput, error) {
	const kPublicKey = "public_key"
	const kEphemeralPublicKey = "epk"
	const kEphemeralPublicKeySignature = "epk_signature"

	const kTimestamp = "timestamp"
	const kSignature = "signature"
	const kDeviceId = "device_id"
	const kExpiresAt = "expires_at_secs"

	body, err := validator.GetValidatedBody(r, validator.VMap{
		kPublicKey: validator.RequiredStringValidators(kPublicKey),
		kTimestamp: validator.RequiredStringValidators(kTimestamp),
		kSignature: validator.RequiredStringValidators(kSignature),
		kDeviceId:  validator.RequiredStringValidators(kDeviceId),
	})
	rootKey := body[kPublicKey].(string)
	ephemeralPublicKey := ""
	ephemeralPublicKeySignature := ""
	var ephemeralKeyExpiration int64 = 0
	if body[kEphemeralPublicKey] != nil {
		result, ok := body[kEphemeralPublicKey].(string)
		if ok {
			signature, ok := body[kEphemeralPublicKeySignature].(string)
			if !ok {
				return nil, gohttplib.HTTP400("when epk provided, epk_signature must be a string")
			}
			if body[kExpiresAt] == nil {
				return nil, gohttplib.HTTP400("when epk provided, expires_at_secs must be provided")
			}
			expiresAt, ok := body[kExpiresAt].(float64)
			if !ok {
				return nil, gohttplib.HTTP400("when epk provided, expires_at_sec must be a number")
			}
			ephemeralKeyExpiration = int64(expiresAt)
			ephemeralPublicKey = result
			ephemeralPublicKeySignature = signature
		}
	}
	if err != nil {
		return nil, err
	}
	return &AnonymousSignInput{
		EphemeralPublicKey:          ephemeralPublicKey,
		PublicKey:                   rootKey,
		EphemeralPublicKeySignature: ephemeralPublicKeySignature,
		ExpiresAt:                   ephemeralKeyExpiration,
		Signature:                   body[kSignature].(string),
		Timestamp:                   body[kTimestamp].(string),
		DeviceId:                    body[kDeviceId].(string),
	}, nil
}
