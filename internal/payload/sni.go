package payload

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
)

// Private TLS SNI derivation, mirrored from @remnawave/node >= 3.3.0
// (src/common/utils/decode-node-payload/decode-servername.util.ts).
//
// The panel derives the same server name from its JWT public key and CA
// certificate and uses it as the TLS SNI when connecting to the node. When
// SNI_VERIFICATION is enabled the node rejects handshakes whose SNI does not
// match this value.

const sniHKDFInfo = "rw-v1"

var (
	sniPEMArmor  = regexp.MustCompile(`-----[^-]+-----`)
	sniNonBase64 = regexp.MustCompile(`[^A-Za-z0-9+/=]`)
	sniTLDs      = [...]string{"com", "net", "org", "io", "dev", "app"}
)

// DeriveSNI reproduces the private server name from the CA certificate and JWT
// public key PEMs. Both PEMs are expected to be normalized (real newlines).
func DeriveSNI(caCertPEM, jwtPublicKeyPEM string) (string, error) {
	canonical := func(value string) string {
		value = sniPEMArmor.ReplaceAllString(value, "")
		return sniNonBase64.ReplaceAllString(value, "")
	}

	ikm := []byte(canonical(jwtPublicKeyPEM) + canonical(caCertPEM))
	if len(ikm) == 0 {
		return "", fmt.Errorf("derive SNI: empty key material")
	}

	okm := hkdfSHA256(ikm, nil, []byte(sniHKDFInfo), 22)
	host := hex.EncodeToString(okm[:16])
	mid := hex.EncodeToString(okm[16:21])
	tld := sniTLDs[int(okm[21])%len(sniTLDs)]
	return host + "." + mid + "." + tld, nil
}

// hkdfSHA256 implements RFC 5869 HKDF-SHA256 using the standard library. salt
// may be nil (a zero-length HMAC key is equivalent to a HashLen of zeros once
// HMAC pads the key to its block size).
func hkdfSHA256(ikm, salt, info []byte, outLen int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}

	// HKDF-Extract: PRK = HMAC-Hash(salt, IKM).
	prk := make([]byte, sha256.Size)
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	copy(prk, mac.Sum(nil))

	// HKDF-Expand: T(i) = HMAC-Hash(PRK, T(i-1) | info | i).
	out := make([]byte, 0, outLen)
	var block []byte
	for counter := byte(1); len(out) < outLen; counter++ {
		mac := hmac.New(sha256.New, prk)
		mac.Write(block)
		mac.Write(info)
		mac.Write([]byte{counter})
		block = mac.Sum(nil)
		out = append(out, block...)
	}
	return out[:outLen]
}
