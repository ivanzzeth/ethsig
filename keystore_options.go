package ethsig

// KeystoreOption configures a KeystoreSigner at construction time.
//
// Options are variadic on every constructor, so existing call sites keep
// working unchanged and keep their current behaviour.
type KeystoreOption func(*keystoreOptions)

type keystoreOptions struct {
	holdKeyUnlocked bool
}

func newKeystoreOptions(opts []KeystoreOption) keystoreOptions {
	var o keystoreOptions
	for _, apply := range opts {
		if apply != nil {
			apply(&o)
		}
	}
	return o
}

// WithKeyHeldUnlocked keeps the account unlocked for the lifetime of the
// signer, so each signature is one secp256k1 operation instead of a full key
// derivation.
//
// # What it buys
//
// Without it, every signing call goes through SignHashWithPassphrase /
// SignTxWithPassphrase, and go-ethereum implements those as *decrypt the
// keystore file, sign, wipe the key again*. The decryption is scrypt, and its
// cost is set by the kdfparams inside the keystore file — not by the
// KeystoreScryptConfig passed at construction, which only applies to files this
// process creates.
//
// Per signature, on an Apple M-series laptop:
//
//	kdfparams in the file   default    WithKeyHeldUnlocked
//	N=4096   (light)        46 ms      22 µs      BenchmarkSignHash, this repo
//	N=262144 (standard)     ~500 ms    unchanged  measured through remote-signer
//
// The light figure is the cheap end and still a factor of two thousand. Most
// tools write standard params, and go-ethereum's own StandardScryptN is 262144.
//
// If signing sits on a path with a deadline — landing in a block, answering a
// quote — that derivation is very likely the largest single item on it.
//
// # What it costs
//
// The private key stays decrypted inside the KeyStore until Close is called.
// That is a real change in exposure, which is why it is opt-in: a caller who
// has not thought about it gets the conservative behaviour, not the fast one.
//
// The stored password is wiped once the account is unlocked, since signing no
// longer needs it. So this trades "password resident, key derived per
// signature" for "key resident, password gone".
//
// # If something else locks the KeyStore
//
// NewKeystoreSigner accepts a KeyStore owned by the caller, so another holder
// can Lock the account. When that happens the signer reports the failure
// instead of silently re-deriving:
//
//	keystore signer: account is locked ... (constructed WithKeyHeldUnlocked)
//
// Re-deriving would put the very cost this option removes back onto an
// unpredictable request. A latency cliff that appears once in a while is harder
// to find than an error that names its cause.
func WithKeyHeldUnlocked() KeystoreOption {
	return func(o *keystoreOptions) { o.holdKeyUnlocked = true }
}
