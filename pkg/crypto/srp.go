// Package crypto — SRP-6a (Secure Remote Password) implementation.
//
// Uses RFC 5054 4096-bit group with SHA-256.
// The server NEVER sees the plaintext password: it stores only a one-way
// verifier derived from the password. During login, a zero-knowledge proof
// exchange (M1/M2) authenticates the client without transmitting the password.
//
// Protocol references:
//   - RFC 2945  (original SRP)
//   - RFC 5054  (TLS-SRP, group parameters)
//   - Tom Wu's SRP-6a addendum
//
// Key separation: the SRP salt (srpSalt) is distinct from the Argon2id salt
// (keySalt) used to derive the AES key that protects the private key.
// They serve different purposes and must never be confused.
package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// srpNHex is the 4096-bit safe prime N from RFC 5054, Appendix A, Group 18.
// Generator g = 5.
const srpNHex = "" +
	"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1" +
	"29024e088a67cc74020bbea63b139b22514a08798e3404dd" +
	"ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245" +
	"e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed" +
	"ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3d" +
	"c2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f" +
	"83655d23dca3ad961c62f356208552bb9ed529077096966d" +
	"670c354e4abc9804f1746c08ca18217c32905e462e36ce3b" +
	"e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9" +
	"de2bcbf6955817183995497cea956ae515d2261898fa0510" +
	"15728e5a8aaac42dad33170d04507a33a85521abdf1cba64" +
	"ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7" +
	"abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6b" +
	"f12ffa06d98a0864d87602733ec86a64521f2b18177b200c" +
	"bbe117577a615d6c770988c0bad946e208e24fa074e5ab31" +
	"43db5bfce0fd108e4b82d120a92108011a723c12a787e6d7" +
	"88719a10bdba5b2699c327186af4e23c1a946834b6150bda" +
	"2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6" +
	"287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed" +
	"1f612970cee2d7afb81bdd762170481cd0069127d5b05aa9" +
	"93b4ea988d8fddc186ffb7dc90a6c08f4df435c934063199" +
	"ffffffffffffffff"

const srpNSize = 512 // bytes — 4096 bits

var (
	srpN *big.Int      // 4096-bit safe prime
	srpG = big.NewInt(5) // generator (RFC 5054 group 18)
	srpK *big.Int      // SRP-6a multiplier: H(N || PAD(g))
)

func init() {
	nBytes, err := hex.DecodeString(srpNHex)
	if err != nil {
		panic("srp: invalid N constant: " + err.Error())
	}
	srpN = new(big.Int).SetBytes(nBytes)

	// k = H(N || PAD(g))  per SRP-6a
	h := sha256.New()
	h.Write(srpPad(srpN))
	h.Write(srpPad(srpG))
	srpK = new(big.Int).SetBytes(h.Sum(nil))
}

// srpPad zero-pads a big.Int to srpNSize bytes (big-endian).
func srpPad(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) >= srpNSize {
		return b
	}
	padded := make([]byte, srpNSize)
	copy(padded[srpNSize-len(b):], b)
	return padded
}

// srpH returns SHA-256 of the concatenation of all provided byte slices.
func srpH(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// srpComputeX computes the SRP private key x = H(salt || H(email ":" password)).
// email is canonicalised to lowercase before hashing.
func srpComputeX(saltBytes []byte, email, password string) *big.Int {
	identity := []byte(strings.ToLower(strings.TrimSpace(email)) + ":" + password)
	hIdentity := srpH(identity)
	x := srpH(saltBytes, hIdentity)
	return new(big.Int).SetBytes(x)
}

// ── Client-side API ─────────────────────────────────────────────────────────

// SRPClientState holds the client's in-memory state during an SRP handshake.
// It is created by SRPClientInit and consumed by SRPClientFinish /
// SRPClientVerifyServer. Do not serialise or persist it.
type SRPClientState struct {
	email    string
	password string
	salt     []byte   // raw SRP salt bytes (received from server)
	a        *big.Int // client private ephemeral (secret)
	A        *big.Int // client public ephemeral  A = g^a mod N
	M2       []byte   // expected server proof (set by SRPClientFinish)
}

// GenerateSRPVerifier derives the SRP salt and verifier for a new account.
// The verifier is a one-way value: the server stores (srpSalt, srpVerifier)
// and cannot reverse them to recover the password.
//
// Returns hex-encoded srpSalt (16 bytes) and srpVerifier (up to 512 bytes).
func GenerateSRPVerifier(email, password string) (srpSaltHex, srpVerifierHex string, err error) {
	saltBytes, err := randomBytes(16)
	if err != nil {
		return "", "", fmt.Errorf("srp: generate verifier: %w", err)
	}

	x := srpComputeX(saltBytes, email, password)
	v := new(big.Int).Exp(srpG, x, srpN) // v = g^x mod N

	return hex.EncodeToString(saltBytes), hex.EncodeToString(v.Bytes()), nil
}

// SRPClientInit begins the client side of the SRP-6a login handshake.
//
// Call this after receiving the server's challenge (srp_salt and
// server_ephemeral) from the /auth/srp/init/ endpoint.
//
// Returns:
//   - state: keep alive until SRPClientVerifyServer
//   - clientEphemeralHex: send to server as "client_ephemeral" in the verify step
func SRPClientInit(email, password, srpSaltHex string) (*SRPClientState, string, error) {
	saltBytes, err := hex.DecodeString(srpSaltHex)
	if err != nil {
		return nil, "", fmt.Errorf("srp: invalid salt hex: %w", err)
	}

	// Generate random private ephemeral a (256-bit).
	var a *big.Int
	for {
		aBytes, err := randomBytes(32)
		if err != nil {
			return nil, "", fmt.Errorf("srp: generate ephemeral: %w", err)
		}
		a = new(big.Int).SetBytes(aBytes)
		if a.Sign() > 0 {
			break
		}
	}

	A := new(big.Int).Exp(srpG, a, srpN) // A = g^a mod N
	if new(big.Int).Mod(A, srpN).Sign() == 0 {
		return nil, "", errors.New("srp: degenerate client ephemeral (A mod N == 0); retry")
	}

	state := &SRPClientState{
		email:    strings.ToLower(strings.TrimSpace(email)),
		password: password,
		salt:     saltBytes,
		a:        a,
		A:        A,
	}
	return state, hex.EncodeToString(srpPad(A)), nil
}

// SRPClientFinish computes the client proof M1 given the server's public
// ephemeral B. M1 proves to the server that the client knows the password
// without transmitting it.
//
// Internally also computes and stores the expected server proof M2 so that
// SRPClientVerifyServer can check it.
//
// Returns clientProofHex (M1) to send to the server as "client_proof".
func SRPClientFinish(state *SRPClientState, serverEphemeralHex string) (string, error) {
	BBytes, err := hex.DecodeString(serverEphemeralHex)
	if err != nil {
		return "", fmt.Errorf("srp: invalid server ephemeral hex: %w", err)
	}
	B := new(big.Int).SetBytes(BBytes)

	if new(big.Int).Mod(B, srpN).Sign() == 0 {
		return "", errors.New("srp: degenerate server ephemeral (B mod N == 0)")
	}

	// u = H(PAD(A) || PAD(B))
	u := new(big.Int).SetBytes(srpH(srpPad(state.A), srpPad(B)))
	if u.Sign() == 0 {
		return "", errors.New("srp: scrambling parameter u is zero")
	}

	// x = H(salt || H(email:password))
	x := srpComputeX(state.salt, state.email, state.password)

	// Premaster secret S = (B - k·g^x)^(a + u·x) mod N
	//
	// Step 1: base = (B - k·g^x) mod N
	gx := new(big.Int).Exp(srpG, x, srpN)   // g^x mod N
	kgx := new(big.Int).Mul(srpK, gx)       // k·g^x
	base := new(big.Int).Sub(B, kgx)        // B - k·g^x  (may be negative)
	base.Mod(base, srpN)                     // reduce mod N
	if base.Sign() < 0 {
		base.Add(base, srpN) // ensure positive representative
	}

	// Step 2: exponent = a + u·x
	exp := new(big.Int).Add(state.a, new(big.Int).Mul(u, x))

	S := new(big.Int).Exp(base, exp, srpN)

	// Session key K = H(PAD(S))
	K := srpH(srpPad(S))

	// M1 = H( H(N) XOR H(g)  ||  H(I)  ||  salt  ||  PAD(A)  ||  PAD(B)  ||  K )
	hN := srpH(srpPad(srpN))
	hG := srpH(srpPad(srpG))
	xorNG := make([]byte, sha256.Size)
	for i := range xorNG {
		xorNG[i] = hN[i] ^ hG[i]
	}
	hI := srpH([]byte(state.email))

	M1 := srpH(xorNG, hI, state.salt, srpPad(state.A), srpPad(B), K)

	// Expected server proof M2 = H( PAD(A) || M1 || K )
	state.M2 = srpH(srpPad(state.A), M1, K)

	return hex.EncodeToString(M1), nil
}

// SRPClientVerifyServer checks the server's proof M2 using constant-time
// comparison. A mismatch indicates a rogue or compromised server.
//
// Must be called after SRPClientFinish.
func SRPClientVerifyServer(state *SRPClientState, serverM2Hex string) error {
	serverM2, err := hex.DecodeString(serverM2Hex)
	if err != nil {
		return fmt.Errorf("srp: invalid server proof hex: %w", err)
	}
	if len(state.M2) == 0 {
		return errors.New("srp: incomplete state — call SRPClientFinish first")
	}
	if subtle.ConstantTimeCompare(serverM2, state.M2) != 1 {
		return errors.New("srp: server proof mismatch — possible MITM attack")
	}
	return nil
}

// ── Server-side helpers (used in tests to simulate the backend) ─────────────
//
// Production deployments implement these in the backend.
// They are included here so the auth_test package can run a full SRP
// round-trip without mocking magic bytes.

// SRPServerState holds server-side ephemeral state for one login attempt.
// It is short-lived: created by SRPServerInit, consumed by SRPServerVerify,
// then discarded. Never persist it.
type SRPServerState struct {
	b    *big.Int // server private ephemeral (secret)
	B    *big.Int // server public ephemeral  B = (k·v + g^b) mod N
	v    *big.Int // user's SRP verifier (loaded from storage)
	salt []byte   // user's SRP salt     (loaded from storage)
}

// SRPServerInit starts the server side of the SRP handshake.
//
// saltHex and verifierHex are the values stored at registration time.
// Returns serverEphemeralHex (B) to send to the client as "server_ephemeral".
func SRPServerInit(saltHex, verifierHex string) (*SRPServerState, string, error) {
	saltBytes, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, "", fmt.Errorf("srp server: invalid salt: %w", err)
	}
	vBytes, err := hex.DecodeString(verifierHex)
	if err != nil {
		return nil, "", fmt.Errorf("srp server: invalid verifier: %w", err)
	}
	v := new(big.Int).SetBytes(vBytes)

	// Generate random server private ephemeral b.
	var b *big.Int
	for {
		bBytes, err := randomBytes(32)
		if err != nil {
			return nil, "", fmt.Errorf("srp server: generate ephemeral: %w", err)
		}
		b = new(big.Int).SetBytes(bBytes)
		if b.Sign() > 0 {
			break
		}
	}

	// B = (k·v + g^b) mod N
	kv := new(big.Int).Mul(srpK, v)
	gb := new(big.Int).Exp(srpG, b, srpN)
	B := new(big.Int).Mod(new(big.Int).Add(kv, gb), srpN)

	if new(big.Int).Mod(B, srpN).Sign() == 0 {
		return nil, "", errors.New("srp server: degenerate server ephemeral; retry")
	}

	state := &SRPServerState{b: b, B: B, v: v, salt: saltBytes}
	return state, hex.EncodeToString(srpPad(B)), nil
}

// SRPServerVerify validates the client proof M1 and returns the server proof M2.
//
// email must be the canonical (lowercased, trimmed) identity string.
// clientEphemeralHex is A, clientProofHex is M1.
// Returns serverProofHex (M2) on success; an error if M1 is wrong.
func SRPServerVerify(state *SRPServerState, email, clientEphemeralHex, clientProofHex string) (string, error) {
	ABytes, err := hex.DecodeString(clientEphemeralHex)
	if err != nil {
		return "", fmt.Errorf("srp server: invalid client ephemeral: %w", err)
	}
	A := new(big.Int).SetBytes(ABytes)
	if new(big.Int).Mod(A, srpN).Sign() == 0 {
		return "", errors.New("srp server: degenerate client ephemeral (A mod N == 0)")
	}

	// u = H(PAD(A) || PAD(B))
	u := new(big.Int).SetBytes(srpH(srpPad(A), srpPad(state.B)))

	// Server premaster secret S = (A · v^u)^b mod N
	vu := new(big.Int).Exp(state.v, u, srpN)  // v^u mod N
	Avu := new(big.Int).Mul(A, vu)            // A · v^u
	S := new(big.Int).Exp(Avu, state.b, srpN) // (A · v^u)^b mod N

	K := srpH(srpPad(S))

	// Reconstruct expected M1
	hN := srpH(srpPad(srpN))
	hG := srpH(srpPad(srpG))
	xorNG := make([]byte, sha256.Size)
	for i := range xorNG {
		xorNG[i] = hN[i] ^ hG[i]
	}
	canonEmail := strings.ToLower(strings.TrimSpace(email))
	hI := srpH([]byte(canonEmail))

	expectedM1 := srpH(xorNG, hI, state.salt, srpPad(A), srpPad(state.B), K)

	clientM1, err := hex.DecodeString(clientProofHex)
	if err != nil {
		return "", fmt.Errorf("srp server: invalid client proof hex: %w", err)
	}
	if subtle.ConstantTimeCompare(clientM1, expectedM1) != 1 {
		return "", errors.New("srp: authentication failed — wrong password")
	}

	// M2 = H( PAD(A) || M1 || K )
	M2 := srpH(srpPad(A), expectedM1, K)
	return hex.EncodeToString(M2), nil
}
