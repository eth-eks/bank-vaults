package vault

import (
	"encoding/base64"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockKVService implements KVService interface for testing
type mockKVService struct {
	store map[string][]byte
}

func newMockKVService() *mockKVService {
	return &mockKVService{
		store: make(map[string][]byte),
	}
}

func (m *mockKVService) Set(key string, value []byte) error {
	m.store[key] = value
	return nil
}

func (m *mockKVService) Get(key string) ([]byte, error) {
	if value, ok := m.store[key]; ok {
		return value, nil
	}
	return nil, &notFoundErrorImpl{}
}

// notFoundErrorImpl implements notFoundError interface
type notFoundErrorImpl struct{}

func (e *notFoundErrorImpl) NotFound() bool {
	return true
}

func (e *notFoundErrorImpl) Error() string {
	return "key not found"
}

func TestFinishRekey(t *testing.T) {
	// Create a mock KV service
	mockStore := newMockKVService()

	// Create a test vault instance
	v := &vault{
		keyStore: mockStore,
	}

	// Create test data
	testValue := []byte("test-value")

	// Create a test response with base64 encoded keys
	resp := &api.RekeyUpdateResponse{
		KeysB64: []string{
			base64.StdEncoding.EncodeToString(testValue),
		},
	}

	// Create test PGP keys
	pgpKeys := []string{"test-user"}

	// Test finishRekey
	err := v.finishRekey(resp, pgpKeys)
	require.NoError(t, err)

	// Verify the key was stored
	keyID := pgpKeys[0] + "-" + keyUnsealForID(0)
	storedValue, err := mockStore.Get(keyID)
	require.NoError(t, err)

	// Verify the stored value matches the original value
	assert.Equal(t, testValue, storedValue)
}

func TestKeyPGPSet(t *testing.T) {
	// Create a mock KV service
	mockStore := newMockKVService()

	// Create a test vault instance
	v := &vault{
		keyStore: mockStore,
	}

	// Create test data
	testValue := []byte("test-value")

	// Base64 encode the test value
	encodedValue := base64.StdEncoding.EncodeToString(testValue)

	// Test keyPGPSet
	err := v.keyPGPSet("test-key", []byte(encodedValue))
	require.NoError(t, err)

	// Verify the stored value matches the original value
	storedValue, err := mockStore.Get("test-key")
	require.NoError(t, err)
	assert.Equal(t, testValue, storedValue)
}
