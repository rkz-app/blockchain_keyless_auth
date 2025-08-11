package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/techpro-studio/gohttplib"
	"golang.org/x/crypto/sha3"
)

type UseCase struct {
	repository        Repository
	chain             Chain
	allowMultipleKeys bool
	sharedSecret      string
	jwtIssuer         string
}

func NewUseCase(repository Repository, chain Chain, sharedSecret string, jwtIssuer string, allowMultipleKeys bool) *UseCase {
	return &UseCase{repository: repository, chain: chain, sharedSecret: sharedSecret, jwtIssuer: jwtIssuer, allowMultipleKeys: allowMultipleKeys}
}

func (uc *UseCase) SignIn(ctx context.Context, input *SignInput) (*SignInOutput, error) {
	onChainAddress, err := uc.chain.ExtractAddressFromSignInput(ctx, input)
	if err != nil {
		return nil, err
	}
	return uc.SignInWithPublicKeyAddressExpires(ctx, "", input.EphemeralPublicKey, *onChainAddress, input.DeviceId, input.ExpiresAt)
}

func (uc *UseCase) SignInWithPublicKeyAddressExpires(ctx context.Context, publicKey string, ephemeralPublicKey string, address string, deviceId string, expiresAt int64) (*SignInOutput, error) {
	if !uc.allowMultipleKeys {
		err := uc.repository.DeleteUserKeys(ctx, address)
		if err != nil {
			return nil, err
		}
	}

	userKey, err := uc.repository.CreateUserKey(ctx, publicKey, ephemeralPublicKey, uc.chain.GetName(), address, deviceId, expiresAt)

	if err != nil {
		return nil, err
	}
	claims := jwt.MapClaims{
		"iss": uc.jwtIssuer,
		"aud": userKey.ID,
		"sub": fmt.Sprintf("%s.%s", userKey.Address, userKey.DeviceId),
		"iat": time.Now().Unix(),
	}
	var zero int64
	if expiresAt != zero {
		claims["exp"] = expiresAt
	}
	tokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := tokenObj.SignedString([]byte(uc.sharedSecret))
	if err != nil {
		return nil, err
	}
	return &SignInOutput{Token: token}, nil
}

func (uc *UseCase) GetUserKeyFromToken(ctx context.Context, token string) (*UserKey, error) {
	tokenObj, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(uc.sharedSecret), nil
	})

	if err != nil {
		return nil, err
	}
	claims, ok := tokenObj.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token")
	}
	issuer, err := claims.GetIssuer()
	if err != nil {
		return nil, err
	}
	if issuer != uc.jwtIssuer {
		return nil, fmt.Errorf("invalid token")
	}

	userKey, err := uc.repository.GetUserKey(ctx, claims["aud"].(string))
	if err != nil {
		return nil, err
	}

	return userKey, nil
}

func (uc *UseCase) RevokeUserKey(ctx context.Context, currentUserKey *UserKey, key string) error {
	if currentUserKey.ID != key {
		userKey, err := uc.repository.GetUserKey(ctx, key)
		if err != nil {
			return err
		}
		if userKey == nil {
			return gohttplib.HTTP404(key)
		}
		if userKey.Address != currentUserKey.Address {
			return gohttplib.HTTP403("Permission denied. You are not authorized to access this resource")
		}
	}
	return uc.repository.DeleteUserKey(ctx, key)
}

func (uc *UseCase) VerifyAnonymousSignInput(ctx context.Context, input *AnonymousSignInput) (*string, error) {
	signerKey := input.PublicKey
	var zeroString string
	if input.EphemeralPublicKey != zeroString {
		signatureBytes, err := hex.DecodeString(input.EphemeralPublicKeySignature)
		if err != nil {
			return nil, gohttplib.HTTP400("when epk provided, epk_signature must be hex")
		}
		ephemeralPublicKeyBytes, err := hex.DecodeString(input.EphemeralPublicKey)
		if err != nil {
			return nil, gohttplib.HTTP400("when epk provided, epk must be hex")
		}
		rootKeyBytes, err := hex.DecodeString(input.PublicKey)
		if err != nil {
			return nil, gohttplib.HTTP400("when epk provided, public_key must be hex")
		}
		verified := ed25519.Verify(rootKeyBytes[2:], ephemeralPublicKeyBytes, signatureBytes)
		if !verified {
			return nil, gohttplib.HTTP400("when epk provided, epk_signature must be signed with public key")
		}
		signerKey = input.EphemeralPublicKey
	}
	publicKey, err := hex.DecodeString(signerKey)
	if err != nil {
		return nil, err
	}
	signature, err := hex.DecodeString(input.Signature)
	if err != nil {
		return nil, err
	}
	verified := ed25519.Verify(publicKey[2:], []byte(input.Timestamp+input.DeviceId), signature)
	if !verified {
		return nil, gohttplib.HTTP403("Signature verification failed")
	}
	address, err := uc.GenerateAddressFromPublicKey(input.PublicKey)
	if err != nil {
		return nil, err
	}
	return &address, nil
}

func (uc *UseCase) GenerateAddressFromPublicKey(publicKey string) (string, error) {
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return "", err
	}

	payload := append(publicKeyBytes, byte(2))

	hash := sha3.New256()
	hash.Write(payload)
	address := hash.Sum(nil)
	addressHex := hex.EncodeToString(address)

	return addressHex, nil
}
