package keystore

import (
	"os"
	"testing"

	ethkeystore "github.com/ethereum/go-ethereum/accounts/keystore"
)

func TestMain(m *testing.M) {
	// Use LightScrypt for all tests to avoid timeouts with race detection.
	defaultScryptN = ethkeystore.LightScryptN
	defaultScryptP = ethkeystore.LightScryptP
	os.Exit(m.Run())
}
