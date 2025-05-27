package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"github.com/techpro-studio/gohttplib"
	"golang.org/x/crypto/sha3"
	"time"
)
import "github.com/dgrijalva/jwt-go"

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
	if !uc.allowMultipleKeys {
		err := uc.repository.DeleteUserKeys(ctx, *onChainAddress)
		if err != nil {
			return nil, err
		}
	}
	return uc.SignInWithPublicKeyAddressExpires(ctx, input.PublicKey, *onChainAddress, input.DeviceId, &input.ExpiresAt)
}

func (uc *UseCase) SignInWithPublicKeyAddressExpires(ctx context.Context, publicKey string, address string, deviceId string, expiresAt *int64) (*SignInOutput, error) {
	userKey, err := uc.repository.CreateUserKey(ctx, publicKey, uc.chain.GetName(), address, deviceId, expiresAt)

	if err != nil {
		return nil, err
	}
	claims := jwt.StandardClaims{
		Issuer:   uc.jwtIssuer,
		Audience: userKey.ID,
		Subject:  fmt.Sprintf("%s.%s", userKey.Address, userKey.DeviceId),
		IssuedAt: time.Now().Unix(),
	}
	if expiresAt != nil {
		claims.ExpiresAt = *expiresAt
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
	if claims["iss"] != uc.jwtIssuer {
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
	publicKey, err := hex.DecodeString(input.PublicKey)
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
