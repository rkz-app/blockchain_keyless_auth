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
		IdToken:   body[kIdToken].(string),
		PublicKey: body[kPublicKey].(string),
		DeviceId:  body[kDeviceId].(string),
		Blinder:   body[kBlinder].(string),
		ExpiresAt: expiresAt,
		UidKey:    body[kUidKey].(string),
	}, nil
}

func ParseAnonymousInput(r *http.Request) (*AnonymousSignInput, error) {
	const kPublicKey = "public_key"
	const kTimestamp = "timestamp"
	const kSignature = "signature"
	const kDeviceId = "device_id"
	body, err := validator.GetValidatedBody(r, validator.VMap{
		kPublicKey: validator.RequiredStringValidators(kPublicKey),
		kTimestamp: validator.RequiredStringValidators(kTimestamp),
		kSignature: validator.RequiredStringValidators(kSignature),
		kDeviceId:  validator.RequiredStringValidators(kDeviceId),
	})
	if err != nil {
		return nil, err
	}
	return &AnonymousSignInput{
		PublicKey: body[kPublicKey].(string),
		Signature: body[kTimestamp].(string),
		Timestamp: body[kSignature].(string),
		DeviceId:  body[kDeviceId].(string),
	}, nil
}
