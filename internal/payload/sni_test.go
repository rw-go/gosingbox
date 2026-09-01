package payload

import "testing"

// TestDeriveSNIMatchesOfficial pins the HKDF-derived private SNI against the
// value produced by @remnawave/node's decode-servername.util.ts for the same
// inputs (verified against the official Node implementation).
func TestDeriveSNIMatchesOfficial(t *testing.T) {
	ca := "-----BEGIN CERTIFICATE-----\nMIIBCgKCAQEA0\n-----END CERTIFICATE-----"
	jwtKey := "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----"

	want := "920ffd3647dba3f415cd57382dd71910.f6807ab641.io"

	got, err := DeriveSNI(ca, jwtKey)
	if err != nil {
		t.Fatalf("derive error: %v", err)
	}
	if got != want {
		t.Fatalf("SNI mismatch:\n got=%s\nwant=%s", got, want)
	}
}

func TestDeriveSNIEmptyMaterial(t *testing.T) {
	if _, err := DeriveSNI("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----", "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----"); err == nil {
		t.Fatal("expected error for empty key material")
	}
}
