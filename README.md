# vault-seal-dev

A server that lets HashiCorp Vault auto-unseal in development, without a cloud KMS. It answers Vault's transit seal on a Unix socket, encrypting and decrypting with an OpenPGP key kept in a file.

**For development only.** Whoever can read the key file can unseal Vault. In production, use a seal backed by a KMS.

Run one beside each Vault node, all with the same key.

## Usage

Make an OpenPGP key without a passphrase, with an encryption subkey, and export it:

```bash
$ gpg --batch --passphrase '' --quick-generate-key 'vault seal' ed25519 cert never
$ gpg --batch --passphrase '' --quick-add-key <fingerprint> cv25519 encr never
$ gpg --export-secret-keys <fingerprint> > key.gpg
```

Then:

```bash
$ export VAULT_SEAL_DEV_KEY=key.gpg
$ vault-seal-dev -socket /run/vault-seal/kms.sock
```

| Option | Required | Description |
|---|---|---|
| `-socket <path>` | yes | Unix socket to listen on. Created with mode 0660 |

`VAULT_SEAL_DEV_KEY` is the path of the exported secret key: exactly one key, binary, not protected by a passphrase.

Run it as a user in the `vault` group, so that the Vault server can use the socket.

## Vault Configuration

```hcl
seal "transit" {
  address         = "unix:///run/vault-seal/kms.sock"
  mount_path      = "transit/"
  key_name        = "dev"
  disable_renewal = "true"
}
```

`key_name` is always `dev`: a request for any other name is refused, with the name to use. vault-seal-dev logs the fingerprint of the key it loaded at start.

After its `vault:v1:` prefix, a ciphertext is a base64 OpenPGP message to that key: `gpg -d` decrypts it too.

## License

This project is licensed under the [MIT License](./LICENSE).
