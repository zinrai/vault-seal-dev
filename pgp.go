package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

type pgpKey struct {
	entity      *openpgp.Entity
	fingerprint string
}

// One key, binary as gpg --export-secret-keys writes it, not a keyring:
// the seal has exactly one key to encrypt to and decrypt with.
func loadKey(path string) (*pgpKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ring, err := openpgp.ReadKeyRing(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(ring) != 1 {
		return nil, fmt.Errorf("%s: %d keys, want exactly one", path, len(ring))
	}
	e := ring[0]
	if e.PrivateKey == nil {
		return nil, fmt.Errorf("%s: a public key, not a secret key", path)
	}
	if e.PrivateKey.Encrypted {
		return nil, fmt.Errorf("%s: protected by a passphrase, which a seal cannot type", path)
	}
	return &pgpKey{entity: e, fingerprint: hex.EncodeToString(e.PrimaryKey.Fingerprint)}, nil
}

func (k *pgpKey) Encrypt(_ context.Context, _ string, plaintext []byte) (string, error) {
	var buf bytes.Buffer
	w, err := openpgp.Encrypt(&buf, []*openpgp.Entity{k.entity}, nil, nil, &packet.Config{})
	if err != nil {
		return "", err
	}
	if _, err := w.Write(plaintext); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func (k *pgpKey) Decrypt(_ context.Context, _ string, ciphertext string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("ciphertext is not base64: %w", err)
	}
	md, err := openpgp.ReadMessage(bytes.NewReader(b), openpgp.EntityList{k.entity}, nil, &packet.Config{})
	if err != nil {
		return nil, err
	}
	if !md.IsEncrypted {
		return nil, errors.New("not an encrypted message")
	}
	// Read to the end before use, not as it arrives: OpenPGP reports a
	// tampered message only once its body has been read.
	return io.ReadAll(md.UnverifiedBody)
}
