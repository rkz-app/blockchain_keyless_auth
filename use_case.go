package auth

import (
	"context"
	"fmt"
	"github.com/techpro-studio/gohttplib"
	"time"
)
import "github.com/dgrijalva/jwt-go"

type UseCase struct {
	repository   Repository
	chain        Chain
	sharedSecret string
	jwtIssuer    string
}

func NewUseCase(repository Repository, chain Chain, sharedSecret string, jwtIssuer string) *UseCase {
	return &UseCase{repository: repository, chain: chain, sharedSecret: sharedSecret, jwtIssuer: jwtIssuer}
}

func (uc *UseCase) SignIn(ctx context.Context, input *SignInput) (*SignInOutput, error) {
	onChainAddress, err := uc.chain.ExtractAddressFromSignInput(ctx, input)
	if err != nil {
		return nil, err
	}
	userKey, err := uc.repository.CreateUserKey(ctx, input.PublicKey, uc.chain.GetName(), *onChainAddress, input.ExpiresAt)
	if err != nil {
		return nil, err
	}
	claims := jwt.StandardClaims{
		ExpiresAt: input.ExpiresAt,
		Issuer:    uc.jwtIssuer,
		Audience:  userKey.ID,
		Subject:   userKey.Address,
		IssuedAt:  time.Now().Unix(),
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
