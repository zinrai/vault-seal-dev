package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Fixed, not configured or derived from the key: there is one key, and a
// node configured for any other seal must be told so at its first request.
// The name also says, wherever key_name is read, that this is the
// development seal.
const keyName = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "vault-seal-dev: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	socket := flag.String("socket", "", "Unix socket to listen on (required)")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()
	if *showVersion {
		printVersion()
		return nil
	}
	if *socket == "" {
		flag.Usage()
		return errors.New("-socket is required")
	}
	// From the environment only, not a flag, and a path, not the key: the
	// key stays in a file the deployment controls.
	keyPath := os.Getenv("VAULT_SEAL_DEV_KEY")
	if keyPath == "" {
		return errors.New("VAULT_SEAL_DEV_KEY, the path of the OpenPGP secret key, is required")
	}

	k, err := loadKey(keyPath)
	if err != nil {
		return err
	}
	l, err := listen(*socket)
	if err != nil {
		return err
	}
	// Loud, not a line among the others: like Vault's dev mode, this must
	// never be mistaken for a seal fit for production.
	slog.Warn("DEVELOPMENT ONLY: the seal key is a file on this host, so anyone who can read it can unseal Vault. Do not use in production.", "key", keyPath)
	slog.Info("serving", "socket", *socket, "key_name", keyName, "fingerprint", k.fingerprint)
	return serve(l, transitHandler(k, keyName))
}

// A Unix socket, not TCP on loopback: on loopback any local process could
// ask for the seal key to be decrypted. Group-writable, not world: the
// vault service reaches it through its group.
func listen(socket string) (net.Listener, error) {
	if err := os.Remove(socket); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	l, err := net.Listen("unix", socket)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socket, 0o660); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

func serve(l net.Listener, h http.Handler) error {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	if err := srv.Serve(l); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
