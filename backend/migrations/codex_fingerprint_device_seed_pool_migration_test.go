package migrations

import (
	"strings"
	"testing"
)

func TestDeviceSeedPoolDefaultMigrationIsBoundedAndPreservesExistingPools(t *testing.T) {
	raw, err := FS.ReadFile("235_codex_fingerprint_device_seed_pool_default.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, required := range []string{
		"GREATEST(3, (extra->>'codex_fingerprint_seed_count')::int)",
		"BETWEEN 1 AND 16",
		"base_seeds ||",
		"codex_fingerprint_seeds",
		"codex_fingerprint_seed_count",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration is missing %q", required)
		}
	}
	if strings.Contains(strings.ToUpper(sql), "DELETE FROM") {
		t.Fatal("device seed migration must not delete account data")
	}
}
