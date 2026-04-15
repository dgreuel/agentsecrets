package crypto

import (
	"strings"
	"testing"
)

// TestSRPRoundTrip verifies a complete SRP-6a handshake: registration,
// challenge generation, client proof, and mutual verification.
func TestSRPRoundTrip(t *testing.T) {
	email := "alice@example.com"
	password := "correct-horse-battery-staple"

	// ── Registration ─────────────────────────────────────────────────────────
	saltHex, verifierHex, err := GenerateSRPVerifier(email, password)
	if err != nil {
		t.Fatalf("GenerateSRPVerifier: %v", err)
	}
	if saltHex == "" || verifierHex == "" {
		t.Fatal("GenerateSRPVerifier returned empty strings")
	}

	// ── Server init (generates B) ─────────────────────────────────────────────
	serverState, serverEphemeralHex, err := SRPServerInit(saltHex, verifierHex)
	if err != nil {
		t.Fatalf("SRPServerInit: %v", err)
	}

	// ── Client init (generates A) ─────────────────────────────────────────────
	clientState, clientEphemeralHex, err := SRPClientInit(email, password, saltHex)
	if err != nil {
		t.Fatalf("SRPClientInit: %v", err)
	}

	// ── Client finish (computes M1) ────────────────────────────────────────────
	clientProofHex, err := SRPClientFinish(clientState, serverEphemeralHex)
	if err != nil {
		t.Fatalf("SRPClientFinish: %v", err)
	}

	// ── Server verify (checks M1, returns M2) ─────────────────────────────────
	serverProofHex, err := SRPServerVerify(serverState, email, clientEphemeralHex, clientProofHex)
	if err != nil {
		t.Fatalf("SRPServerVerify: %v", err)
	}

	// ── Client verify server proof (M2) ───────────────────────────────────────
	if err := SRPClientVerifyServer(clientState, serverProofHex); err != nil {
		t.Fatalf("SRPClientVerifyServer: %v", err)
	}
}

// TestSRPWrongPassword checks that the wrong password fails M1 verification.
func TestSRPWrongPassword(t *testing.T) {
	email := "bob@example.com"
	saltHex, verifierHex, _ := GenerateSRPVerifier(email, "correct-password")

	serverState, serverEphemeralHex, _ := SRPServerInit(saltHex, verifierHex)

	// Attacker uses wrong password
	clientState, clientEphemeralHex, _ := SRPClientInit(email, "wrong-password", saltHex)
	clientProofHex, _ := SRPClientFinish(clientState, serverEphemeralHex)

	_, err := SRPServerVerify(serverState, email, clientEphemeralHex, clientProofHex)
	if err == nil {
		t.Fatal("expected server to reject wrong password, but it accepted")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestSRPMITM simulates a man-in-the-middle swapping the server proof.
func TestSRPMITM(t *testing.T) {
	email := "carol@example.com"
	saltHex, verifierHex, _ := GenerateSRPVerifier(email, "secret")

	serverState, serverEphemeralHex, _ := SRPServerInit(saltHex, verifierHex)
	clientState, clientEphemeralHex, _ := SRPClientInit(email, "secret", saltHex)
	clientProofHex, _ := SRPClientFinish(clientState, serverEphemeralHex)

	// Get real M2
	realM2, _ := SRPServerVerify(serverState, email, clientEphemeralHex, clientProofHex)

	// Tamper: flip one byte
	tampered := []byte(realM2)
	tampered[0] ^= 0xFF
	tamperedHex := string(tampered)

	err := SRPClientVerifyServer(clientState, tamperedHex)
	if err == nil {
		t.Fatal("expected client to reject tampered server proof, but it accepted")
	}
}

// TestSRPEmailCaseInsensitive ensures email case-folding is applied consistently.
func TestSRPEmailCaseInsensitive(t *testing.T) {
	saltHex, verifierHex, _ := GenerateSRPVerifier("Alice@Example.COM", "pw")

	serverState, serverEphemeralHex, _ := SRPServerInit(saltHex, verifierHex)
	clientState, clientEphemeralHex, _ := SRPClientInit("ALICE@EXAMPLE.COM", "pw", saltHex)
	clientProofHex, _ := SRPClientFinish(clientState, serverEphemeralHex)

	serverProofHex, err := SRPServerVerify(serverState, "alice@example.com", clientEphemeralHex, clientProofHex)
	if err != nil {
		t.Fatalf("email case folding: SRPServerVerify: %v", err)
	}
	if err := SRPClientVerifyServer(clientState, serverProofHex); err != nil {
		t.Fatalf("email case folding: SRPClientVerifyServer: %v", err)
	}
}

// TestGenerateSRPVerifierDifferentSalts checks that two registrations produce
// different salts and verifiers even for the same credentials.
func TestGenerateSRPVerifierDifferentSalts(t *testing.T) {
	s1, v1, _ := GenerateSRPVerifier("user@test.com", "password")
	s2, v2, _ := GenerateSRPVerifier("user@test.com", "password")

	if s1 == s2 {
		t.Error("two registrations produced identical salts")
	}
	if v1 == v2 {
		t.Error("two registrations produced identical verifiers")
	}
}

// TestSRPVerifierNotPassword confirms the verifier hex does not contain the
// password string (sanity check that no cleartext leaks).
func TestSRPVerifierNotPassword(t *testing.T) {
	password := "super-secret-password-12345"
	_, verifierHex, _ := GenerateSRPVerifier("u@example.com", password)
	if strings.Contains(verifierHex, password) {
		t.Error("verifier hex appears to contain the plaintext password")
	}
}
