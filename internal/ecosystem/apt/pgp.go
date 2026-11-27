package apt

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Signer signs Release files with tspackages' own key.
type Signer struct {
	entity *openpgp.Entity // private keys decrypted
	keyID  uint64          // the signing (sub)key chosen at load
	public []byte          // armored public key
}

// LoadSigner reads one armored private key, decrypting it with passphrase if
// it is encrypted. The primary key and the signing (sub)key must each be
// Ed25519 as legacy EdDSA (algorithm 22, which apt's gpgv verifies) or RSA
// of at least 3072 bits, and a signing-capable key with its
// private part must be valid now.
func LoadSigner(armored, passphrase string) (*Signer, error) {
	el, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armored))
	if err != nil {
		return nil, fmt.Errorf("apt: signing key: %w", err)
	}
	if len(el) != 1 {
		return nil, fmt.Errorf("apt: signing key: want exactly one key, got %d", len(el))
	}
	e := el[0]
	if e.PrivateKey == nil {
		return nil, errors.New("apt: signing key holds no private key")
	}
	if encrypted(e) {
		if passphrase == "" {
			return nil, errors.New("apt: signing key is encrypted and no passphrase is set")
		}
		if err := e.DecryptPrivateKeys([]byte(passphrase)); err != nil {
			return nil, fmt.Errorf("apt: decrypting signing key: %w", err)
		}
	}
	k, ok := e.SigningKey(time.Now())
	if !ok || k.PrivateKey == nil || k.PrivateKey.Dummy() || k.PrivateKey.Encrypted {
		return nil, errors.New("apt: signing key has no valid signing-capable key with a private part")
	}
	for _, pk := range []*packet.PublicKey{e.PrimaryKey, k.PublicKey} {
		if err := checkKeyAlgorithm(pk); err != nil {
			return nil, err
		}
	}
	var pub bytes.Buffer
	w, err := armor.Encode(&pub, openpgp.PublicKeyType, nil)
	if err != nil {
		return nil, err
	}
	if err := e.Serialize(w); err != nil {
		return nil, fmt.Errorf("apt: serializing public key: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	pub.WriteByte('\n')
	return &Signer{entity: e, keyID: k.PublicKey.KeyId, public: pub.Bytes()}, nil
}

func encrypted(e *openpgp.Entity) bool {
	if e.PrivateKey.Encrypted {
		return true
	}
	for _, sub := range e.Subkeys {
		if sub.PrivateKey != nil && sub.PrivateKey.Encrypted {
			return true
		}
	}
	return false
}

func checkKeyAlgorithm(pk *packet.PublicKey) error {
	switch pk.PubKeyAlgo {
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSASignOnly:
		if bits, err := pk.BitLength(); err != nil || bits < 3072 {
			return fmt.Errorf("apt: signing key %s: RSA keys need at least 3072 bits", pk.KeyIdString())
		}
		return nil
	case packet.PubKeyAlgoEdDSA:
		if c, err := pk.Curve(); err == nil && c == packet.Curve25519 {
			return nil
		}
	case packet.PubKeyAlgoEd25519:
		return fmt.Errorf("apt: signing key %s: use a legacy (v4, EdDSA) Ed25519 key; apt's gpgv can't verify RFC 9580 Ed25519 keys", pk.KeyIdString())
	default:
	}
	return fmt.Errorf("apt: signing key %s: only Ed25519 (legacy EdDSA) and RSA keys are supported", pk.KeyIdString())
}

// signingKey is the key chosen at load, as long as it is still valid.
func (s *Signer) signingKey() (*packet.PrivateKey, error) {
	k, ok := s.entity.SigningKeyById(time.Now(), s.keyID)
	if !ok {
		return nil, fmt.Errorf("apt: signing key %016X is no longer valid", s.keyID)
	}
	return k.PrivateKey, nil
}

// ClearSign returns the InRelease for a Release file: release clear-signed so
// that the signed text, read the way apt reads it, is release byte for byte.
// release must end in a newline and must not hold CR or trailing blanks on a
// line, which clear-signing would change.
func (s *Signer) ClearSign(release []byte) ([]byte, error) {
	switch {
	case len(release) == 0 || release[len(release)-1] != '\n':
		return nil, errors.New("apt: clear-signed text must end in a newline")
	case bytes.IndexByte(release, '\r') >= 0:
		return nil, errors.New("apt: clear-signed text must not hold CR")
	case bytes.Contains(release, []byte(" \n")) || bytes.Contains(release, []byte("\t\n")):
		return nil, errors.New("apt: clear-signed text must not hold trailing blanks")
	}
	key, err := s.signingKey()
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	w, err := clearsign.Encode(&b, key, nil)
	if err != nil {
		return nil, err
	}
	// The line ending before the signature belongs to the armor, as gpg
	// writes it; the reader adds the final newline back.
	if _, err := w.Write(release[:len(release)-1]); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// DetachSign returns the armored binary signature of release (Release.gpg).
func (s *Signer) DetachSign(release []byte) ([]byte, error) {
	if _, err := s.signingKey(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&b, s.entity, bytes.NewReader(release), &packet.Config{SigningKeyId: s.keyID}); err != nil {
		return nil, err
	}
	b.WriteByte('\n')
	return b.Bytes(), nil
}

// PublicKey returns the armored public key (primary key, user IDs, subkeys
// and their signatures); it never holds private key material.
func (s *Signer) PublicKey() []byte { return bytes.Clone(s.public) }

// Fingerprint is the primary key's fingerprint in uppercase hex.
func (s *Signer) Fingerprint() string {
	return strings.ToUpper(hex.EncodeToString(s.entity.PrimaryKey.Fingerprint))
}

// Caps on upstream signature verification. Every signature packet whose
// issuer names a keyring key costs a hash of the whole signed text, and
// issuer key IDs are public, so the packets examined are capped (real
// repositories carry one to three) along with the input sizes.
const (
	maxSignatures   = 32
	maxDetachedSig  = 64 << 10
	maxReportedErrs = 3
)

// Keyring holds the public keys an upstream's Release must be signed by.
type Keyring struct{ el openpgp.EntityList }

// LoadKeyring reads OpenPGP public keys: binary packets, or one or more
// armored public key blocks.
func LoadKeyring(b []byte) (*Keyring, error) {
	var el openpgp.EntityList
	if rest := bytes.TrimLeft(b, " \t\r\n"); bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
		for len(bytes.TrimSpace(rest)) > 0 {
			end := bytes.Index(rest, []byte("\n-----END "))
			if end < 0 {
				return nil, errors.New("apt: keyring: unterminated armored block")
			}
			n := len(rest)
			if nl := bytes.IndexByte(rest[end+1:], '\n'); nl >= 0 {
				n = end + 1 + nl + 1
			}
			blk, err := armor.Decode(bytes.NewReader(rest[:n]))
			if err != nil {
				return nil, fmt.Errorf("apt: keyring: %w", err)
			}
			if blk.Type != openpgp.PublicKeyType {
				return nil, fmt.Errorf("apt: keyring: unexpected %q block", blk.Type)
			}
			es, err := openpgp.ReadKeyRing(blk.Body)
			if err != nil {
				return nil, fmt.Errorf("apt: keyring: %w", err)
			}
			el = append(el, es...)
			rest = rest[n:]
		}
	} else {
		es, err := openpgp.ReadKeyRing(bytes.NewReader(b))
		if err != nil {
			return nil, fmt.Errorf("apt: keyring: %w", err)
		}
		el = es
	}
	if len(el) == 0 {
		return nil, errors.New("apt: keyring holds no keys")
	}
	return &Keyring{el}, nil
}

// VerifyInRelease checks a clear-signed InRelease and returns its signed text
// as apt reads it: every line newline-terminated. The input must be exactly
// one signed message, with nothing before or after it.
func (k *Keyring) VerifyInRelease(b []byte, now time.Time) ([]byte, error) {
	if len(b) > MaxRelease {
		return nil, fmt.Errorf("apt: InRelease exceeds %d bytes", MaxRelease)
	}
	if !bytes.HasPrefix(b, []byte("-----BEGIN PGP SIGNED MESSAGE-----")) {
		return nil, errors.New("apt: InRelease does not start with a signed message")
	}
	blk, rest := clearsign.Decode(b)
	if blk == nil {
		return nil, errors.New("apt: InRelease is not a valid signed message")
	}
	if len(rest) != 0 {
		return nil, errors.New("apt: InRelease holds data after the signature")
	}
	if blk.ArmoredSignature.Type != openpgp.SignatureType {
		return nil, fmt.Errorf("apt: InRelease signature block is %q", blk.ArmoredSignature.Type)
	}
	if err := k.verify(blk.Bytes, blk.ArmoredSignature.Body, now); err != nil {
		return nil, err
	}
	return append(blk.Plaintext, '\n'), nil
}

// VerifyDetached checks sig (Release.gpg, armored or binary) over release.
func (k *Keyring) VerifyDetached(release, sig []byte, now time.Time) error {
	if len(release) > MaxRelease {
		return fmt.Errorf("apt: Release exceeds %d bytes", MaxRelease)
	}
	if len(sig) > maxDetachedSig {
		return fmt.Errorf("apt: Release.gpg exceeds %d bytes", maxDetachedSig)
	}
	var r io.Reader = bytes.NewReader(sig)
	if bytes.HasPrefix(bytes.TrimLeft(sig, " \t\r\n"), []byte("-----BEGIN ")) {
		blk, err := armor.Decode(r)
		if err != nil {
			return fmt.Errorf("apt: Release.gpg: %w", err)
		}
		if blk.Type != openpgp.SignatureType {
			return fmt.Errorf("apt: Release.gpg holds a %q block", blk.Type)
		}
		r = blk.Body
	}
	return k.verify(release, r, now)
}

// verify succeeds if any signature packet in sigs is a valid signature of
// signed by a key in the keyring at now. Signatures by other keys, ones that
// fail and packets go-crypto can't parse (v3 signatures, unknown versions or
// algorithms) are skipped; any other packet is an error, and so is a block
// of more than maxSignatures packets.
func (k *Keyring) verify(signed []byte, sigs io.Reader, now time.Time) error {
	pr := packet.NewReader(sigs)
	var errs []error
	n := 0
	for ; ; n++ {
		p, err := pr.NextWithUnsupported()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("apt: reading signatures: %w", err)
		}
		if n == maxSignatures {
			return fmt.Errorf("apt: signature block holds more than %d packets", maxSignatures)
		}
		switch p := p.(type) {
		case *packet.Signature:
			err = k.check(signed, p, now)
		case *packet.UnsupportedPacket:
			err = fmt.Errorf("unsupported packet: %w", p.Error)
		default:
			return fmt.Errorf("apt: signature block holds a %T packet", p)
		}
		if err == nil {
			return nil
		}
		if len(errs) < maxReportedErrs {
			errs = append(errs, err)
		}
	}
	if n == 0 {
		return errors.New("apt: no signature found")
	}
	if n > len(errs) {
		errs = append(errs, fmt.Errorf("%d more", n-len(errs)))
	}
	return fmt.Errorf("apt: no valid signature by a key in the keyring: %w", errors.Join(errs...))
}

func (k *Keyring) check(signed []byte, sig *packet.Signature, now time.Time) error {
	// A nil config applies go-crypto's default rejection lists: SHA-1, MD5
	// and RIPEMD-160 message hashes, DSA and ElGamal keys.
	var policy *packet.Config
	if sig.SigType != packet.SigTypeBinary && sig.SigType != packet.SigTypeText {
		return fmt.Errorf("signature type %#x", sig.SigType)
	}
	if policy.RejectMessageHashAlgorithm(sig.Hash) {
		return fmt.Errorf("weak hash %v", sig.Hash)
	}
	if policy.RejectPublicKeyAlgorithm(sig.PubKeyAlgo) {
		return fmt.Errorf("rejected key algorithm %d", sig.PubKeyAlgo)
	}
	if sig.IssuerKeyId == nil {
		return errors.New("signature names no issuer")
	}
	err := fmt.Errorf("unknown issuer %016X", *sig.IssuerKeyId)
	for _, key := range k.el.KeysByIdUsage(*sig.IssuerKeyId, packet.KeyFlagSign) {
		if !sig.CheckKeyIdOrFingerprint(key.PublicKey) {
			continue
		}
		h, herr := sig.PrepareVerify()
		if herr != nil {
			return herr
		}
		w := io.Writer(h)
		if sig.SigType == packet.SigTypeText {
			w = openpgp.NewCanonicalTextHash(h)
		}
		if _, err := w.Write(signed); err != nil {
			return err
		}
		if err = key.PublicKey.VerifySignature(h, sig); err != nil {
			err = fmt.Errorf("key %s: %w", key.PublicKey.KeyIdString(), err)
			continue
		}
		// Another copy of the key in the keyring (a refreshed export, say)
		// may still be valid at now.
		if err = keyValid(key, sig, now); err == nil {
			return nil
		}
	}
	return err
}

// keyValid is go-crypto's check of a verified message signature, at now: no
// unknown critical notation, primary key, signing subkey and primary identity
// not revoked, neither key expired, and none of the signature, the primary
// self-signature, the subkey binding and its cross-signature expired or
// made after now.
func keyValid(key openpgp.Key, sig *packet.Signature, now time.Time) error {
	id := key.PublicKey.KeyIdString()
	self, identity := key.Entity.PrimarySelfSignature()
	if self == nil {
		return fmt.Errorf("key %s: no primary self-signature", id)
	}
	bySubkey := key.PublicKey != key.Entity.PrimaryKey
	sigs := []*packet.Signature{sig, self}
	if bySubkey {
		if key.SelfSignature == nil || key.SelfSignature.EmbeddedSignature == nil {
			return fmt.Errorf("key %s: signing subkey without a cross-signed binding", id)
		}
		sigs = append(sigs, key.SelfSignature, key.SelfSignature.EmbeddedSignature)
	}
	for _, s := range sigs {
		for _, n := range s.Notations {
			if n.IsCritical {
				return fmt.Errorf("key %s: unknown critical notation %s", id, n.Name)
			}
		}
	}
	if key.Entity.Revoked(now) || (bySubkey && key.Revoked(now)) || (identity != nil && identity.Revoked(now)) {
		return fmt.Errorf("key %s: revoked", id)
	}
	if key.Entity.PrimaryKey.KeyExpired(self, now) || (bySubkey && key.PublicKey.KeyExpired(key.SelfSignature, now)) {
		return fmt.Errorf("key %s: expired", id)
	}
	for _, s := range sigs {
		if s.SigExpired(now) {
			return fmt.Errorf("key %s: signature expired or made after %s", id, now.UTC().Format(time.RFC3339))
		}
	}
	return nil
}
