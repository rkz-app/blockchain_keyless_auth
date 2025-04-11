package auth

import (
	"fmt"
	"github.com/techpro-studio/gohttplib"
	"net/http"
)

// redirect since apple doesn't support redirect with id_token in uri

func SetupAppleIdTokenRedirectInRouter(router gohttplib.Router, appleCallbackPath string, redirectURI string) {
	router.Post(
		appleCallbackPath,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			err := r.ParseForm()
			if err != nil {
				gohttplib.HTTP400("Unable to parse form").Write(w)
				return
			}
			idToken := r.Form.Get("id_token")
			http.Redirect(w, r, fmt.Sprintf("%s?id_token=%s", redirectURI, idToken), http.StatusTemporaryRedirect)
		}),
	)
}
