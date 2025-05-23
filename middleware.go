package auth

import (
	"context"
	"github.com/techpro-studio/gohttplib"
	"net/http"
	"strings"
)

const CurrentUserKeyContextKey = "current_user_key"

func GetTokenFromRequest(req *http.Request) string {
	tokenStr := ""
	if AuthHeader := req.Header.Get("Authorization"); AuthHeader != "" {
		tokenStr = strings.Split(AuthHeader, " ")[1]
	}
	if tokenStr == "" {
		token := gohttplib.GetParameterFromURLInRequest(req, "token")
		if token != nil {
			tokenStr = *token
		}
	}
	return tokenStr
}

func UserKeyMiddlewareFactory(useCase *UseCase, verifier RequestVerifier) gohttplib.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			tokenStr := GetTokenFromRequest(req)
			if tokenStr == "" {
				gohttplib.HTTP401().Write(w)
				return
			}
			userKey, err := useCase.GetUserKeyFromToken(req.Context(), tokenStr)

			if err != nil {
				gohttplib.SafeConvertToServerError(err).Write(w)
				return
			}
			if userKey == nil {
				gohttplib.HTTP401().Write(w)
				return
			}
			if userKey.isExpired() {
				gohttplib.HTTP401().Write(w)
				return
			}

			verifiedRequest := verifier.VerifyRequest(req, userKey)

			if !verifiedRequest {
				gohttplib.HTTP401().Write(w)
				return
			}

			ctx := context.WithValue(req.Context(), CurrentUserKeyContextKey, userKey)
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	}
}

func GetUserKeyFromRequestForced(req *http.Request) *UserKey {
	usr := GetUserKeyFromRequest(req)
	if usr == nil {
		panic("No current user key")
	}
	return usr
}

func GetUserKeyFromRequest(req *http.Request) *UserKey {
	user, ok := req.Context().Value(CurrentUserKeyContextKey).(*UserKey)
	if !ok {
		return nil
	}
	return user
}
