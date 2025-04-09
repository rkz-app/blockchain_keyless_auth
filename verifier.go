package auth

import "net/http"

type RequestVerifier interface {
	VerifyRequest(r *http.Request, key *UserKey) bool
}

type NoRequestVerifier struct{}

func NewNoRequestVerifier() *NoRequestVerifier {
	return &NoRequestVerifier{}
}

func (n NoRequestVerifier) VerifyRequest(r *http.Request, key *UserKey) bool {
	return true
}
