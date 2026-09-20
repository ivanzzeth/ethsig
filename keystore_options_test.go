package ethsig

import (
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// newSignerForOptions builds a signer over its own KeyStore and hands back both,
// because these tests need to Lock the account from the outside.
func newSignerForOptions(t *testing.T, opts ...KeystoreOption) (*KeystoreSigner, *keystore.KeyStore, common.Address) {
	t.Helper()
	dir := t.TempDir()
	if _, _, err := createTestKeystore(dir, testPassword); err != nil {
		t.Fatalf("create keystore: %v", err)
	}
	ks := newTestKeyStore(dir)
	accs := ks.Accounts()
	if len(accs) != 1 {
		t.Fatalf("want exactly one account in the fixture, got %d", len(accs))
	}
	addr := accs[0].Address
	s, err := NewKeystoreSigner(ks, addr, testPassword, opts...)
	if err != nil {
		t.Fatalf("NewKeystoreSigner: %v", err)
	}
	return s, ks, addr
}

// Which key path a signer takes, told apart without timing anything.
//
// A timing assertion would be both flaky and beside the point. The difference
// that matters is *what the signature depends on*:
//
//   - default: the stored password, so an account locked from the outside
//     changes nothing — it re-derives the key anyway.
//   - WithKeyHeldUnlocked: the unlocked account, so locking it from the outside
//     must make signing fail. That failure is the proof no derivation happened.
//
// If the option ever silently fell back to the passphrase path, the second half
// would start passing and this test would say so.
func TestKeyPathIsDecidedByTheOption(t *testing.T) {
	hash := common.HexToHash("0x1234567890123456789012345678901234567890123456789012345678901234")

	t.Run("default re-derives, so an outside Lock is irrelevant", func(t *testing.T) {
		s, ks, addr := newSignerForOptions(t)
		defer func() { _ = s.Close() }()

		if _, err := s.SignHash(hash); err != nil {
			t.Fatalf("baseline signing must work, or the rest proves nothing: %v", err)
		}
		if err := ks.Lock(addr); err != nil {
			t.Fatalf("Lock: %v", err)
		}
		if _, err := s.SignHash(hash); err != nil {
			t.Fatalf("a locked account stopped the default signer — it is supposed to "+
				"hold the password and derive the key per call, so Lock cannot affect it: %v", err)
		}
	})

	t.Run("WithKeyHeldUnlocked uses the unlocked account", func(t *testing.T) {
		s, ks, addr := newSignerForOptions(t, WithKeyHeldUnlocked())
		defer func() { _ = s.Close() }()

		if _, err := s.SignHash(hash); err != nil {
			t.Fatalf("baseline signing must work, or the rest proves nothing: %v", err)
		}
		if err := ks.Lock(addr); err != nil {
			t.Fatalf("Lock: %v", err)
		}
		_, err := s.SignHash(hash)
		if err == nil {
			t.Fatal("signing still worked after the account was locked — so it fell back " +
				"to the passphrase and ran a key derivation. That is the exact cost this " +
				"option exists to remove, and nothing would have reported it.")
		}
		if !strings.Contains(err.Error(), "WithKeyHeldUnlocked") {
			t.Errorf("the error must name why this signer cannot recover on its own, "+
				"or the reader sees a bare ErrLocked and goes looking in the wrong place; got: %v", err)
		}
	})
}

// Every signing method must take the same path. The branch lives in one helper
// precisely so that a method added later cannot get the other half by accident —
// this pins that, because such a slip is invisible until someone profiles it.
func TestEverySigningMethodHonoursTheOption(t *testing.T) {
	s, ks, addr := newSignerForOptions(t, WithKeyHeldUnlocked())
	defer func() { _ = s.Close() }()

	tx := types.NewTransaction(0, common.HexToAddress("0x1"), big.NewInt(1), 21000, big.NewInt(1), nil)
	hash := common.HexToHash("0xabc")
	// 0x19 0x01 <domain separator> <hash struct> — the EIP-191 form the
	// validator accepts; a bare string is rejected before it ever reaches a key.
	eip191 := append([]byte("\x19\x01"), crypto.Keccak256Hash([]byte("domain")).Bytes()...)
	eip191 = append(eip191, crypto.Keccak256Hash([]byte("struct")).Bytes()...)

	calls := map[string]func() error{
		"SignHash":                   func() error { _, err := s.SignHash(hash); return err },
		"PersonalSign":               func() error { _, err := s.PersonalSign("hi"); return err },
		"SignEIP191Message":          func() error { _, err := s.SignEIP191Message(string(eip191)); return err },
		"SignRawMessage":             func() error { _, err := s.SignRawMessage([]byte("hi")); return err },
		"SignTransactionWithChainID": func() error { _, err := s.SignTransactionWithChainID(tx, big.NewInt(1)); return err },
	}

	for name, call := range calls {
		if err := call(); err != nil {
			t.Fatalf("%s failed before the account was locked: %v", name, err)
		}
	}

	if err := ks.Lock(addr); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	for name, call := range calls {
		if err := call(); err == nil {
			t.Errorf("%s kept working after Lock — it is still going through the "+
				"passphrase, so it pays a full key derivation on every call while the "+
				"other methods do not", name)
		}
	}
}

// Close must relock, or the decrypted key outlives the signer that owns it —
// and "I closed it" is exactly the point a caller stops thinking about the key.
func TestCloseRelocksAHeldAccount(t *testing.T) {
	s, ks, addr := newSignerForOptions(t, WithKeyHeldUnlocked())

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Ask the KeyStore directly: a still-unlocked account signs, a locked one
	// returns ErrLocked.
	acct, err := ks.Find(accounts.Account{Address: addr})
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	_, err = ks.SignHash(acct, common.HexToHash("0x1").Bytes())
	if !errors.Is(err, keystore.ErrLocked) {
		t.Fatalf("after Close the account is still unlocked (got %v) — the key is "+
			"sitting decrypted in a KeyStore whose signer is gone", err)
	}
}

// What the option is worth, measured rather than asserted.
//
// ⛔ Not a test: a timing threshold would be flaky on shared CI, and the point
// is not that some number is met — it is the *shape* of the difference. Run it
// when the question comes up:
//
//	go test -bench BenchmarkSignHash -benchtime 20x .
//
// The default path's cost is set by the kdfparams inside the keystore file, not
// by anything passed at construction. These fixtures use LightScryptN, which is
// the cheap end; a file written with StandardScryptN (what most tools produce,
// N=262144) costs roughly fifty times more per signature, while the held-key
// path does not move.
func BenchmarkSignHash(b *testing.B) {
	hash := common.HexToHash("0x1234")

	build := func(b *testing.B, opts ...KeystoreOption) *KeystoreSigner {
		b.Helper()
		dir := b.TempDir()
		if _, _, err := createTestKeystore(dir, testPassword); err != nil {
			b.Fatalf("create keystore: %v", err)
		}
		ks := newTestKeyStore(dir)
		addr := ks.Accounts()[0].Address
		s, err := NewKeystoreSigner(ks, addr, testPassword, opts...)
		if err != nil {
			b.Fatalf("NewKeystoreSigner: %v", err)
		}
		return s
	}

	b.Run("default", func(b *testing.B) {
		s := build(b)
		defer func() { _ = s.Close() }()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := s.SignHash(hash); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("WithKeyHeldUnlocked", func(b *testing.B) {
		s := build(b, WithKeyHeldUnlocked())
		defer func() { _ = s.Close() }()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := s.SignHash(hash); err != nil {
				b.Fatal(err)
			}
		}
	})
}
