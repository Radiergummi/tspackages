package apt

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/radiergummi/tspackages/internal/testutil"
)

const testRelease = "Origin: tspackages\nLabel: hosted\nSuite: bookworm\nDescription: first\n second\n .\nSHA256:\n " +
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 0 main/binary-amd64/Packages\n"

func newEntity(t *testing.T, name string, cfg *packet.Config) *openpgp.Entity {
	t.Helper()
	if cfg == nil {
		cfg = &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA}
	}
	e, err := openpgp.NewEntity(name, "", name+"@example.com", cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func armorPrivate(t *testing.T, e *openpgp.Entity) string {
	t.Helper()
	return testutil.ArmorPGP(t, openpgp.PrivateKeyType, func(w io.Writer) error { return e.SerializePrivateWithoutSigning(w, nil) })
}

func keyring(t *testing.T, es ...*openpgp.Entity) *Keyring {
	t.Helper()
	k, err := LoadKeyring([]byte(testutil.ArmorPGP(t, openpgp.PublicKeyType, func(w io.Writer) error {
		for _, e := range es {
			if err := e.Serialize(w); err != nil {
				return err
			}
		}
		return nil
	})))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func signer(t *testing.T, e *openpgp.Entity) *Signer {
	t.Helper()
	s, err := LoadSigner(armorPrivate(t, e), "")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// clearSignMulti clear-signs text with the signing keys of es, one signature
// packet each, in order.
func clearSignMulti(t *testing.T, text string, now time.Time, es ...*openpgp.Entity) []byte {
	t.Helper()
	var keys []*packet.PrivateKey
	for _, e := range es {
		k, ok := e.SigningKey(now)
		if !ok {
			t.Fatal("no signing key")
		}
		keys = append(keys, k.PrivateKey)
	}
	var b bytes.Buffer
	w, err := clearsign.EncodeMulti(&b, keys, &packet.Config{Time: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, strings.TrimSuffix(text, "\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// detachedSig makes a v4 signature of data by k with any hash and signature
// type, as a raw packet.
func detachedSig(t *testing.T, k *packet.PrivateKey, typ packet.SignatureType, h crypto.Hash, data []byte, at time.Time) []byte {
	t.Helper()
	sig := &packet.Signature{
		Version: 4, SigType: typ, PubKeyAlgo: k.PubKeyAlgo, Hash: h, CreationTime: at,
		IssuerKeyId: &k.KeyId, IssuerFingerprint: k.Fingerprint, IssuerKeyVersion: 4,
	}
	hh, err := sig.PrepareSign(nil)
	if err != nil {
		t.Fatal(err)
	}
	w := io.Writer(hh)
	if typ == packet.SigTypeText {
		w = openpgp.NewCanonicalTextHash(hh)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	// The salt notation go-crypto adds by default has no size for SHA-1.
	noSalt := false
	if err := sig.Sign(hh, k, &packet.Config{NonDeterministicSignaturesViaNotation: &noSalt}); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := sig.Serialize(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func armorSig(t *testing.T, packets ...[]byte) []byte {
	t.Helper()
	return []byte(testutil.ArmorPGP(t, openpgp.SignatureType, func(w io.Writer) error {
		_, err := w.Write(bytes.Join(packets, nil))
		return err
	}))
}

func TestSignVerifyRoundTrip(t *testing.T) {
	e := newEntity(t, "a", nil)
	s, k := signer(t, e), keyring(t, e)
	now := time.Now()

	for _, text := range []string{testRelease, "A: b\n", "A: b\n\n", "\n", "A: b\n-c\n--d\n"} {
		in, err := s.ClearSign([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		got, err := k.VerifyInRelease(in, now)
		if err != nil {
			t.Fatalf("VerifyInRelease(%q): %v\n%s", text, err, in)
		}
		if string(got) != text {
			t.Fatalf("VerifyInRelease = %q, want %q", got, text)
		}
	}

	in, err := s.ClearSign([]byte(testRelease))
	if err != nil {
		t.Fatal(err)
	}
	// gpg's layout: no blank line before the signature.
	if !bytes.Contains(in, []byte("Packages\n-----BEGIN PGP SIGNATURE-----")) {
		t.Fatalf("unexpected InRelease layout:\n%s", in)
	}
	i := bytes.Index(in, []byte("hosted"))
	bad := bytes.Clone(in)
	bad[i] = 'H'
	if _, err := k.VerifyInRelease(bad, now); err == nil {
		t.Fatal("flipped byte in InRelease verified")
	}
	for name, b := range map[string][]byte{
		"prefix":   append([]byte("Origin: evil\n"), in...),
		"suffix":   append(bytes.Clone(in), "Origin: evil\n"...),
		"unsigned": []byte(testRelease),
		"twice":    append(bytes.Clone(in), in...),
	} {
		if _, err := k.VerifyInRelease(b, now); err == nil {
			t.Fatalf("%s: verified", name)
		}
	}

	sig, err := s.DetachSign([]byte(testRelease))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(sig, []byte("-----BEGIN PGP SIGNATURE-----")) {
		t.Fatalf("DetachSign not armored: %q", sig)
	}
	if err := k.VerifyDetached([]byte(testRelease), sig, now); err != nil {
		t.Fatal(err)
	}
	flipped := []byte(testRelease)
	flipped[len(flipped)-2] ^= 1
	if err := k.VerifyDetached(flipped, sig, now); err == nil {
		t.Fatal("flipped byte in Release verified")
	}
	if err := k.VerifyDetached([]byte(strings.TrimSuffix(testRelease, "\n")), sig, now); err == nil {
		t.Fatal("binary signature ignored a missing final newline")
	}

	for _, text := range []string{"", "A: b", "A: b \n", "A: b\r\n", "A: b\t\n"} {
		if _, err := s.ClearSign([]byte(text)); err == nil {
			t.Fatalf("ClearSign(%q) accepted text that would not verify to itself", text)
		}
	}
}

func TestVerifyAnyOfSeveralSignatures(t *testing.T) {
	a, b, c := newEntity(t, "a", nil), newEntity(t, "b", nil), newEntity(t, "c", nil)
	now := time.Now()
	in := clearSignMulti(t, testRelease, now, a, b)
	for name, k := range map[string]*Keyring{"A": keyring(t, a), "B": keyring(t, b), "AB": keyring(t, a, b), "CB": keyring(t, c, b)} {
		got, err := k.VerifyInRelease(in, now)
		if err != nil {
			t.Fatalf("keyring {%s}: %v", name, err)
		}
		if string(got) != testRelease {
			t.Fatalf("keyring {%s}: %q", name, got)
		}
	}
	if _, err := keyring(t, c).VerifyInRelease(in, now); err == nil {
		t.Fatal("keyring {C} verified")
	}

	ka, _ := a.SigningKey(now)
	kb, _ := b.SigningKey(now)
	sig := armorSig(t, detachedSig(t, ka.PrivateKey, packet.SigTypeBinary, crypto.SHA256, []byte(testRelease), now),
		detachedSig(t, kb.PrivateKey, packet.SigTypeBinary, crypto.SHA256, []byte(testRelease), now))
	if err := keyring(t, b).VerifyDetached([]byte(testRelease), sig, now); err != nil {
		t.Fatalf("detached, keyring {B}: %v", err)
	}
	if err := keyring(t, c).VerifyDetached([]byte(testRelease), sig, now); err == nil {
		t.Fatal("detached, keyring {C} verified")
	}
}

// A key in the keyring whose signature does not hold (an expired key here)
// does not stop the search: a later valid signature still verifies.
func TestVerifySkipsInvalidSignatureOfKnownKey(t *testing.T) {
	signed := time.Now().Add(-2 * time.Hour)
	old := newEntity(t, "old", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, KeyLifetimeSecs: 3600, Time: func() time.Time { return signed.Add(-time.Minute) }})
	cur := newEntity(t, "cur", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Time: func() time.Time { return signed.Add(-time.Minute) }})
	in := clearSignMulti(t, testRelease, signed, old, cur)
	if _, err := keyring(t, old).VerifyInRelease(in, time.Now()); err == nil {
		t.Fatal("expired key verified")
	}
	if _, err := keyring(t, old, cur).VerifyInRelease(in, time.Now()); err != nil {
		t.Fatalf("keyring {old, cur}: %v", err)
	}
}

func TestVerifySubkeySignature(t *testing.T) {
	e := newEntity(t, "sub", nil)
	if err := e.AddSigningSubkey(&packet.Config{Algorithm: packet.PubKeyAlgoEdDSA}); err != nil {
		t.Fatal(err)
	}
	s := signer(t, e)
	in, err := s.ClearSign([]byte(testRelease))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keyring(t, e).VerifyInRelease(in, time.Now()); err != nil {
		t.Fatal(err)
	}
	primaryOnly := *e
	primaryOnly.Subkeys = nil
	if _, err := keyring(t, &primaryOnly).VerifyInRelease(in, time.Now()); err == nil {
		t.Fatal("verified without the signing subkey: the signature was not made by the subkey")
	}
	if s.Fingerprint() != strings.ToUpper(fingerprintHex(e)) {
		t.Fatalf("Fingerprint = %s, want the primary key's", s.Fingerprint())
	}
}

func fingerprintHex(e *openpgp.Entity) string { return hex.EncodeToString(e.PrimaryKey.Fingerprint) }

func TestVerifyExpiredKey(t *testing.T) {
	now := time.Now()
	e := newEntity(t, "exp", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, KeyLifetimeSecs: 3600, Time: func() time.Time { return now.Add(-30 * time.Minute) }})
	in, err := signer(t, e).ClearSign([]byte(testRelease))
	if err != nil {
		t.Fatal(err)
	}
	k := keyring(t, e)
	if _, err := k.VerifyInRelease(in, now); err != nil {
		t.Fatalf("before expiry: %v", err)
	}
	if _, err := k.VerifyInRelease(in, now.Add(2*time.Hour)); err == nil {
		t.Fatal("verified with an expired key")
	}
	if _, err := k.VerifyInRelease(in, now.Add(-10*time.Minute)); err == nil {
		t.Fatal("verified a signature made after now")
	}
}

func TestVerifyRevokedKey(t *testing.T) {
	e := newEntity(t, "rev", nil)
	in, err := signer(t, e).ClearSign([]byte(testRelease))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.RevokeKey(packet.KeyCompromised, "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := keyring(t, e).VerifyInRelease(in, time.Now()); err == nil {
		t.Fatal("verified with a revoked key")
	}
}

func TestVerifyRejectsWeakHash(t *testing.T) {
	e := newEntity(t, "rsa", &packet.Config{Algorithm: packet.PubKeyAlgoRSA, RSABits: 2048})
	k := keyring(t, e)
	now := time.Now()
	for _, h := range []crypto.Hash{crypto.SHA1, crypto.SHA256} {
		sig := armorSig(t, detachedSig(t, e.PrivateKey, packet.SigTypeBinary, h, []byte(testRelease), now.Add(-time.Second)))
		err := k.VerifyDetached([]byte(testRelease), sig, now)
		if (err == nil) != (h == crypto.SHA256) || (err != nil && !strings.Contains(err.Error(), "weak hash")) {
			t.Fatalf("%v: err = %v", h, err)
		}
	}
	// A text-mode signature is checked over the canonical text.
	sig := armorSig(t, detachedSig(t, e.PrivateKey, packet.SigTypeText, crypto.SHA256, []byte(testRelease), now.Add(-time.Second)))
	if err := k.VerifyDetached([]byte(testRelease), sig, now); err != nil {
		t.Fatalf("text signature: %v", err)
	}
}

func TestLoadKeyring(t *testing.T) {
	a, b := newEntity(t, "a", nil), newEntity(t, "b", nil)
	var bin bytes.Buffer
	if err := a.Serialize(&bin); err != nil {
		t.Fatal(err)
	}
	// Two armored blocks in one file, as keyring files are often concatenated.
	two := testutil.ArmorPGP(t, openpgp.PublicKeyType, a.Serialize) + testutil.ArmorPGP(t, openpgp.PublicKeyType, b.Serialize)
	for name, in := range map[string][]byte{"binary": bin.Bytes(), "armored": []byte(two)} {
		k, err := LoadKeyring(in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		in, err := signer(t, a).ClearSign([]byte(testRelease))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := k.VerifyInRelease(in, time.Now()); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if k, err := LoadKeyring([]byte(two)); err != nil || len(k.el) != 2 {
		t.Fatalf("two armored blocks: %v", err)
	}
	for _, in := range []string{"", "not a key", "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n-----END PGP PUBLIC KEY BLOCK-----\n"} {
		if _, err := LoadKeyring([]byte(in)); err == nil {
			t.Fatalf("LoadKeyring(%q) accepted", in)
		}
	}
}

func TestLoadSigner(t *testing.T) {
	ed := newEntity(t, "ed", nil)
	s, err := LoadSigner(armorPrivate(t, ed), "")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9A-F]{40}$`).MatchString(s.Fingerprint()) || s.Fingerprint() != strings.ToUpper(fingerprintHex(ed)) {
		t.Fatalf("Fingerprint = %q", s.Fingerprint())
	}

	priv, pub := testutil.PGPKey(t, "util")
	us, err := LoadSigner(priv, "")
	if err != nil {
		t.Fatalf("testutil.PGPKey: %v", err)
	}
	uk, err := LoadKeyring([]byte(pub))
	if err != nil {
		t.Fatal(err)
	}
	if in, err := us.ClearSign([]byte(testRelease)); err != nil {
		t.Fatal(err)
	} else if _, err := uk.VerifyInRelease(in, time.Now()); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadSigner(armorPrivate(t, newEntity(t, "rsa3072", &packet.Config{Algorithm: packet.PubKeyAlgoRSA, RSABits: 3072})), ""); err != nil {
		t.Fatalf("RSA 3072: %v", err)
	}
	for name, cfg := range map[string]*packet.Config{
		"RSA 2048": {Algorithm: packet.PubKeyAlgoRSA, RSABits: 2048},
		"ECDSA":    {Algorithm: packet.PubKeyAlgoECDSA, Curve: packet.CurveNistP256},
		"Ed448":    {Algorithm: packet.PubKeyAlgoEd448},
		"expired":  {Algorithm: packet.PubKeyAlgoEdDSA, KeyLifetimeSecs: 60, Time: func() time.Time { return time.Now().Add(-time.Hour) }},
	} {
		if _, err := LoadSigner(armorPrivate(t, newEntity(t, "x", cfg)), ""); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	pub = testutil.ArmorPGP(t, openpgp.PublicKeyType, ed.Serialize)
	if _, err := LoadSigner(pub, ""); err == nil {
		t.Fatal("public key accepted as a signing key")
	}
	if _, err := LoadSigner("garbage", ""); err == nil {
		t.Fatal("garbage accepted")
	}

	enc := newEntity(t, "enc", nil)
	if err := enc.EncryptPrivateKeys([]byte("right"), nil); err != nil {
		t.Fatal(err)
	}
	armored := armorPrivate(t, enc)
	for _, pw := range []string{"", "wrong"} {
		if _, err := LoadSigner(armored, pw); err == nil {
			t.Fatalf("encrypted key loaded with passphrase %q", pw)
		}
	}
	s, err = LoadSigner(armored, "right")
	if err != nil {
		t.Fatal(err)
	}
	in, err := s.ClearSign([]byte(testRelease))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keyring(t, enc).VerifyInRelease(in, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestSignerPublicKey(t *testing.T) {
	e := newEntity(t, "pub", nil)
	if err := e.AddSigningSubkey(&packet.Config{Algorithm: packet.PubKeyAlgoEdDSA}); err != nil {
		t.Fatal(err)
	}
	s := signer(t, e)
	pub := s.PublicKey()
	if !bytes.HasPrefix(pub, []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----")) || bytes.Contains(pub, []byte("PRIVATE")) {
		t.Fatalf("PublicKey:\n%s", pub)
	}
	blk, err := armor.Decode(bytes.NewReader(pub))
	if err != nil {
		t.Fatal(err)
	}
	r := packet.NewReader(blk.Body)
	n := 0
	for {
		p, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := p.(*packet.PrivateKey); ok {
			t.Fatal("PublicKey holds a private key packet")
		}
		n++
	}
	if n == 0 {
		t.Fatal("PublicKey holds no packets")
	}
	k, err := LoadKeyring(pub)
	if err != nil {
		t.Fatal(err)
	}
	in, err := s.ClearSign([]byte(testRelease))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.VerifyInRelease(in, time.Now()); err != nil {
		t.Fatalf("own public key does not verify own InRelease: %v", err)
	}
}
