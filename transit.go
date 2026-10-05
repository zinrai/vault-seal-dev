package main

// Only the two calls of Vault's transit seal, not the whole Transit secrets
// engine: encrypt and decrypt are all a seal makes.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

// Prefixed, not the bare ciphertext: the seal rejects a ciphertext that
// does not split into exactly three fields on ':'.
const prefix = "vault:v1:"

type cipher interface {
	Encrypt(ctx context.Context, keyID string, plaintext []byte) (string, error)
	Decrypt(ctx context.Context, keyID, ciphertext string) ([]byte, error)
}

type transit struct {
	kms   cipher
	keyID string
}

// Only keyID, the key's fingerprint, not any name: a seal configured for
// another key must fail, not have its root key encrypted to this one.
func transitHandler(kms cipher, keyID string) http.Handler {
	t := transit{kms: kms, keyID: keyID}
	mux := http.NewServeMux()
	for _, method := range []string{"PUT", "POST"} {
		mux.HandleFunc(method+" /v1/transit/encrypt/{key}", t.encrypt)
		mux.HandleFunc(method+" /v1/transit/decrypt/{key}", t.decrypt)
	}
	return mux
}

func (t transit) encrypt(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Plaintext string `json:"plaintext"`
	}
	if !t.accept(w, r, &req) {
		return
	}
	plaintext, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		fail(w, http.StatusBadRequest, fmt.Errorf("plaintext is not base64: %w", err))
		return
	}
	ciphertext, err := t.kms.Encrypt(r.Context(), t.keyID, plaintext)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	if strings.Contains(ciphertext, ":") {
		fail(w, http.StatusInternalServerError, errors.New("ciphertext contains ':', which the seal cannot parse"))
		return
	}
	respond(w, map[string]string{"ciphertext": prefix + ciphertext})
}

func (t transit) decrypt(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Ciphertext string `json:"ciphertext"`
	}
	if !t.accept(w, r, &req) {
		return
	}
	ciphertext, ok := strings.CutPrefix(req.Ciphertext, prefix)
	if !ok {
		fail(w, http.StatusBadRequest, fmt.Errorf("ciphertext does not start with %q", prefix))
		return
	}
	plaintext, err := t.kms.Decrypt(r.Context(), t.keyID, ciphertext)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	respond(w, map[string]string{"plaintext": base64.StdEncoding.EncodeToString(plaintext)})
}

func (t transit) accept(w http.ResponseWriter, r *http.Request, body any) bool {
	if key := r.PathValue("key"); key != t.keyID {
		fail(w, http.StatusForbidden, fmt.Errorf("key %q is not served here", key))
		return false
	}
	if err := json.NewDecoder(r.Body).Decode(body); err != nil {
		fail(w, http.StatusBadRequest, err)
		return false
	}
	return true
}

// Wrapped in "data", not bare: that is the shape of a Vault response, and
// the seal reads data.ciphertext and data.plaintext.
func respond(w http.ResponseWriter, data map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

func fail(w http.ResponseWriter, status int, err error) {
	slog.Error("request failed", "status", status, "error", err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{err.Error()}})
}
