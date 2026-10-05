package main

import (
	"bytes"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	transitseal "github.com/hashicorp/go-kms-wrapping/wrappers/transit/v2"
)

func TestVaultsTransitSealRoundTripsThroughTheSocket(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.gpg")
	e, err := openpgp.NewEntity("seal", "", "", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := e.SerializePrivate(&buf, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	k, err := loadKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	socket := filepath.Join(dir, "kms.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: transitHandler(k, k.fingerprint)}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })

	seal := transitseal.NewWrapper()
	if _, err := seal.SetConfig(t.Context(), wrapping.WithConfigMap(map[string]string{
		"address":         "unix://" + socket,
		"mount_path":      "transit/",
		"key_name":        k.fingerprint,
		"disable_renewal": "true",
	})); err != nil {
		t.Fatal(err)
	}

	rootKey := []byte("the root key that unseals Vault")
	blob, err := seal.Encrypt(t.Context(), rootKey)
	if err != nil {
		t.Fatalf("the seal cannot encrypt: %v", err)
	}
	got, err := seal.Decrypt(t.Context(), blob)
	if err != nil {
		t.Fatalf("the seal cannot decrypt what it encrypted: %v", err)
	}
	if !bytes.Equal(got, rootKey) {
		t.Fatalf("the seal decrypted %q, not the root key", got)
	}
}
