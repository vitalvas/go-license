package printer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.vitalvas.com/go-license/license"
)

func writeLicense(t *testing.T, lic *license.License) string {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	encoded, err := lic.Encode(privateKey)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "license.pem")
	require.NoError(t, os.WriteFile(path, encoded, 0o600))

	return path
}

func TestRun_AllFields(t *testing.T) {
	path := writeLicense(t, &license.License{
		ID:           "license-id",
		Customer:     "acme",
		Subscription: "sub-1",
		Type:         "enterprise",
		IssuedAt:     time.Unix(1700000000, 0).Unix(),
		ExpiredAt:    time.Unix(1800000000, 0).Unix(),
		Data:         json.RawMessage(`{"seats":10}`),
	})

	var buf bytes.Buffer
	require.NoError(t, Run(&buf, path))

	out := buf.String()
	assert.Contains(t, out, "License ID: license-id")
	assert.Contains(t, out, "License Customer: acme")
	assert.Contains(t, out, "License Subscription: sub-1")
	assert.Contains(t, out, "License Type: enterprise")
	assert.Contains(t, out, "License Issued At: 1700000000")
	assert.Contains(t, out, "License Expires At: 1800000000")
	assert.Contains(t, out, "License Data:")
	assert.Contains(t, out, `"seats": 10`)
}

func TestRun_MinimalFields(t *testing.T) {
	path := writeLicense(t, &license.License{ID: "minimal"})

	var buf bytes.Buffer
	require.NoError(t, Run(&buf, path))

	out := buf.String()
	assert.Contains(t, out, "License ID: minimal")
	assert.NotContains(t, out, "License Customer:")
	assert.NotContains(t, out, "License Data:")
}

func TestRun_FileNotFound(t *testing.T) {
	var buf bytes.Buffer
	err := Run(&buf, filepath.Join(t.TempDir(), "missing.pem"))
	require.Error(t, err)
}

func TestRun_MalformedLicense(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.pem")
	require.NoError(t, os.WriteFile(path, []byte("not a license"), 0o600))

	var buf bytes.Buffer
	err := Run(&buf, path)
	require.Error(t, err)
}
