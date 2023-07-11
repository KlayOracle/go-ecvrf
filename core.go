//Copyright (c) 2020 - 2023 vechain.org.
//Copyright (c) 2023 digioracle.link
//Licensed under the MIT license.

package ecvrf

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"hash"
	"math/big"
)

type point struct {
	X, Y *big.Int
}

type core struct {
	*Config
	cachedHasher hash.Hash
}

// Q returns prime order of large prime order subgroup.
func (c *core) Q() *big.Int {
	return c.Curve.Params().N
}

// N return half of length, in octets, of a field element in F, rounded up to the nearest even integer
func (c *core) N() int {
	return ((c.Curve.Params().P.BitLen()+1)/2 + 7) / 8
}

func (c *core) getHasher() hash.Hash {
	if c.cachedHasher == nil {
		c.cachedHasher = c.NewHasher()
	} else {
		c.cachedHasher.Reset()
	}
	return c.cachedHasher
}

// Marshal marshals a point into compressed form specified in section 4.3.6 of ANSI X9.62.
// It's the alias of `point_to_string` specified in [draft-irtf-cfrg-vrf-06 section 5.5](https://tools.ietf.org/id/draft-irtf-cfrg-vrf-06.html#rfc.section.5.5).
func (c *core) Marshal(pt *point) []byte {
	return elliptic.MarshalCompressed(c.Curve, pt.X, pt.Y)
}

// Unmarshal unmarshals a compressed point in the form specified in section 4.3.6 of ANSI X9.62.
// It's the alias of `string_to_point` specified in [draft-irtf-cfrg-vrf-06 section 5.5](https://tools.ietf.org/id/draft-irtf-cfrg-vrf-06.html#rfc.section.5.5).
// This is borrowed from the project https://github.com/google/keytransparency.
func (c *core) Unmarshal(in []byte) *point {
	if x, y := c.Decompress(c.Curve, in); x != nil && y != nil {
		return &point{x, y}
	}
	return nil
}

func (c *core) ScalarMult(pt *point, k []byte) *point {
	x, y := c.Curve.ScalarMult(pt.X, pt.Y, k)

	return &point{x, y}
}

func (c *core) ScalarBaseMult(k []byte) *point {

	x, y := c.Curve.ScalarBaseMult(k)
	return &point{x, y}
}

func (c *core) Add(pt1, pt2 *point) *point {
	x, y := c.Curve.Add(pt1.X, pt1.Y, pt2.X, pt2.Y)
	return &point{x, y}
}

func (c *core) Sub(pt1, pt2 *point) *point {
	// pt1 - pt2 = pt1 + invert(pt2),
	// where invert(pt2) = (x2, P - y2)
	x, y := c.Curve.Add(
		pt1.X, pt1.Y,
		pt2.X, new(big.Int).Sub(c.Curve.Params().P, pt2.Y))
	return &point{x, y}
}

// HashToCurveTryAndIncrement takes in the VRF input `alpha` and converts it to H, using the try_and_increment algorithm.
// See: [draft-irtf-cfrg-vrf-06 section 5.4.1.1](https://tools.ietf.org/id/draft-irtf-cfrg-vrf-06.html#rfc.section.5.4.1.1).
func (c *core) HashToCurveTryAndIncrement(pk *point, alpha []byte) (*point, error) {
	hasher := c.getHasher()
	hash := make([]byte, 1+hasher.Size())
	hash[0] = 2 // compress format

	// step 1: ctr = 0
	ctr := 0

	// step 2: PK_string = point_to_string(Y)
	pkBytes := c.Marshal(pk)

	// step 3 ~ 6
	prefix := []byte{c.SuiteString, 0x01}
	suffix := []byte{0}
	for ; ctr < 256; ctr++ {
		// hash_string = Hash(suite_string || one_string || PK_string || alpha_string || ctr_string)
		suffix[0] = byte(ctr)
		hasher.Reset()
		hasher.Write(prefix)
		hasher.Write(pkBytes)
		hasher.Write(alpha)
		hasher.Write(suffix)
		// apppend right after compress format
		hasher.Sum(hash[1:1])

		// H = arbitrary_string_to_point(hash_string)
		if H := c.Unmarshal(hash); H != nil {
			if c.Cofactor > 1 {
				// If H is not "INVALID" and cofactor > 1, set H = cofactor * H
				H = c.ScalarMult(H, []byte{c.Cofactor})
			}
			return H, nil
		}
	}
	return nil, errors.New("no valid point found")
}

// HashToCurveTryAndIncrementV2 takes in the VRF input `alpha` and converts it to H, using the try_and_increment algorithm.
// See: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-10.html#name-ecvrf-hash-to-curve
func (c *core) HashToCurveTryAndIncrementSecp256k1(pk *point, alpha []byte) (*point, error) {
	//hasher := c.getHasher()
	//hash := make([]byte, 1+hasher.Size())
	//hash[0] = 2 // compress format

	// step 1: ctr = 0
	ctr := 0

	// step 2: PK_string = point_to_string(Y)
	pkBytes := c.Marshal(pk)

	// step 3 ~ 6
	//prefix := []byte{c.SuiteString, 0x01}
	//suffix := []byte{0}
	for ; ctr < 256; ctr++ {
		h := sha256.New()
		h.Reset()
		h.Write([]byte{c.SuiteString})
		h.Write([]byte{0x01})
		h.Write(pkBytes)
		h.Write(alpha)
		h.Write([]byte{byte(ctr)})
		h.Write([]byte{0x0})

		hString := hex.EncodeToString(h.Sum(nil))
		hString = "02" + hString

		hWithPrefix, err := hex.DecodeString(hString)
		if err != nil {
			panic(err)
		}

		// H = arbitrary_string_to_point(hash_string)
		if H := c.Unmarshal(hWithPrefix); H != nil {
			if c.Cofactor > 1 {
				// If H is not "INVALID" and cofactor > 1, set H = cofactor * H
				H = c.ScalarMult(H, []byte{c.Cofactor})
			}
			return H, nil
		}
	}
	return nil, errors.New("no valid point found")
}

// See: [draft-irtf-cfrg-vrf-06 section 5.4.3](https://tools.ietf.org/id/draft-irtf-cfrg-vrf-06.html#rfc.section.5.4.3)
func (c *core) HashPoints(points ...*point) *big.Int {
	hasher := c.getHasher()
	hasher.Write([]byte{c.SuiteString, 0x2})
	for _, pt := range points {
		hasher.Write(c.Marshal(pt))
	}
	return bits2int(hasher.Sum(nil), c.N()*8)
}

func (c *core) HashPointsSecp256k1(points ...*point) *big.Int {
	twoBytes := []byte{c.SuiteString, 0x02}

	hh := sha256.New()
	hh.Reset()
	hh.Write(twoBytes)

	for _, pt := range points {
		hh.Write(c.Marshal(pt))
	}

	hh.Write([]byte{0x00})

	cString := hh.Sum(nil)
	truncatedCstring := cString[:16]

	return new(big.Int).SetBytes(truncatedCstring)
}

func (c *core) GammaToHash(gamma *point) []byte {
	gammaCof := gamma
	if c.Cofactor != 1 {
		gammaCof = c.ScalarMult(gamma, []byte{c.Cofactor})
	}
	hasher := c.getHasher()
	hasher.Write([]byte{c.SuiteString, 0x03})
	hasher.Write(c.Marshal(gammaCof))
	return hasher.Sum(nil)
}

func (c *core) GammaToHashSecp256k1(gamma *point) []byte {
	gammaCof := gamma
	if c.Cofactor != 1 {
		gammaCof = c.ScalarMult(gamma, []byte{c.Cofactor})
	}

	h := sha256.New()
	h.Reset()
	h.Write([]byte{c.SuiteString})
	h.Write([]byte{0x03})
	h.Write(c.Marshal(gammaCof))
	h.Write([]byte{0x00})

	return h.Sum(nil)
}

func (c *core) EncodeProof(gamma *point, C, S *big.Int) []byte {
	gammaBytes := c.Marshal(gamma)

	cbytes := int2octets(C, c.N())
	sbytes := int2octets(S, (c.Q().BitLen()+7)/8)

	return append(append(gammaBytes, cbytes...), sbytes...)
}

// See: [draft-irtf-cfrg-vrf-06 section 5.4.4](https://tools.ietf.org/id/draft-irtf-cfrg-vrf-06.html#rfc.section.5.4.4)
func (c *core) DecodeProof(pi []byte) (gamma *point, C, S *big.Int, err error) {
	var (
		ptlen = (c.Curve.Params().BitSize+7)/8 + 1
		clen  = c.N()
		slen  = (c.Q().BitLen() + 7) / 8
	)

	if len(pi) != ptlen+clen+slen {
		err = errors.New("invalid proof length")
		return
	}

	if gamma = c.Unmarshal(pi[:ptlen]); gamma == nil {
		err = errors.New("invalid point")
		return
	}

	C = new(big.Int).SetBytes(pi[ptlen : ptlen+clen])
	S = new(big.Int).SetBytes(pi[ptlen+clen:])
	return
}

// rfc6979nonce generates nonce according to [RFC6979](https://tools.ietf.org/html/rfc6979).
func (c *core) rfc6979nonce(sk *big.Int, m []byte) []byte {
	var (
		q      = c.Q()
		qlen   = q.BitLen()
		rolen  = (qlen + 7) / 8
		hasher = c.getHasher()
	)

	// Step A
	// Process m through the hash function H, yielding:
	// h1 = H(m)
	// (h1 is a sequence of hlen bits).
	hasher.Write(m)
	bx := int2octets(sk, rolen)
	bh := bits2octets(hasher.Sum(nil), q, rolen)

	nonce := secp256k1.NonceRFC6979(bx, bh, nil, nil, 0).Bytes()
	return nonce[:]
}

// https://datatracker.ietf.org/doc/html/rfc6979#section-3.2
func (c *core) rfc6979nonceSecp256k1(sk *big.Int, h []byte) []byte {

	skb := new(big.Int).Set(sk).Bytes()[:32]
	h1 := sha256.Sum256(h)
	K := []byte("0000000000000000000000000000000000000000000000000000000000000000")
	V := []byte("1111111111111111111111111111111111111111111111111111111111111111")
	zeroByte := []byte{0x00}
	oneByte := []byte{0x01}

	//739308f8d19be96040369a5358519ebc6cfc260b941b1f1dc152270e6e07beb1
	hk1 := hmac.New(sha256.New, K)
	hk1.Reset()
	hk1.Write(V)
	hk1.Write(zeroByte)
	hk1.Write(skb)
	hk1.Write(h1[:])

	K = hk1.Sum(nil)

	hv1 := hmac.New(sha256.New, []byte(hex.EncodeToString(K)))
	hv1.Reset()
	hv1.Write(V)

	V = hv1.Sum(nil)

	hk2 := hmac.New(sha256.New, []byte(hex.EncodeToString(K)))
	hk2.Reset()
	hk2.Write([]byte(hex.EncodeToString(V)))
	hk2.Write(oneByte)
	hk2.Write(skb)
	hk2.Write(h1[:])

	K = hk2.Sum(nil)

	hv2 := hmac.New(sha256.New, []byte(hex.EncodeToString(K)))
	hv2.Reset()
	hv2.Write([]byte(hex.EncodeToString(V)))

	V = hv2.Sum(nil)

	hv3 := hmac.New(sha256.New, []byte(hex.EncodeToString(K)))
	hv3.Reset()
	hv3.Write([]byte(hex.EncodeToString(V)))

	V = hv3.Sum(nil)

	return V
}

// https://tools.ietf.org/html/rfc6979#section-2.3.2
func bits2int(in []byte, qlen int) *big.Int {
	out := new(big.Int).SetBytes(in)
	if inlen := len(in) * 8; inlen > qlen {
		return out.Rsh(out, uint(inlen-qlen))
	}
	return out
}

// https://tools.ietf.org/html/rfc6979#section-2.3.3
func int2octets(v *big.Int, rolen int) []byte {
	var (
		out    = v.Bytes()
		outlen = len(out)
	)

	// left pad with zeros if it's too short
	if rolen > outlen {
		out2 := make([]byte, rolen)
		copy(out2[rolen-outlen:], out)
		return out2
	}

	// drop most significant bytes if it's too long
	return out[outlen-rolen:]
}

// https://tools.ietf.org/html/rfc6979#section-2.3.4
func bits2octets(in []byte, q *big.Int, rolen int) []byte {
	z1 := bits2int(in, q.BitLen())
	z2 := new(big.Int).Sub(z1, q)
	if z2.Sign() < 0 {
		return int2octets(z1, rolen)
	}
	return int2octets(z2, rolen)
}
