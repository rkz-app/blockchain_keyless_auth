package auth

import (
	"github.com/techpro-studio/gohttplib"
	"net/http"
)

type Transport struct {
	useCase *UseCase
}

func NewTransport(useCase *UseCase) *Transport {
	return &Transport{useCase: useCase}
}

func (t *Transport) RevokeUserKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	userKey := GetUserKeyFromRequestForced(r)
	key := gohttplib.GetParameterFromURLInRequest(r, "key")
	if key == nil || *key == "" {
		key = &userKey.ID
	}
	err := t.useCase.RevokeUserKey(r.Context(), userKey, *key)
	gohttplib.WriteJsonOrError(w, map[string]int{"ok": 1}, http.StatusOK, err)
}

func (t *Transport) GetUserKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	userKey := GetUserKeyFromRequestForced(r)
	keys, err := t.useCase.GetAllAssociatedUserKeys(r.Context(), userKey)
	gohttplib.WriteJsonOrError(w, keys, http.StatusOK, err)
}

func (t *Transport) SignIn(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	input, err := ParseInput(r)
	if err != nil {
		gohttplib.SafeConvertToServerError(err).Write(w)
		return
	}
	result, err := t.useCase.SignIn(r.Context(), input)
	gohttplib.WriteJsonOrError(w, result, http.StatusOK, err)
}
