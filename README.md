# Note

Golang implementation of Elliptic Curve Verifiable Random Function (VRF).

This library has test to both show the generation of prove in Golang and verification of prove in Solidity using **SECP256K1_SHA256_TAI** cipher suite.

Changes Introduced to [VeChain go-ecvrf](https://github.com/vechain/go-ecvrf) following https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-10.html#name-elliptic-curve-vrf-ecvrf
and https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-10.html#name-ecvrf-ciphersuites includes:

- ProveSecp256k1
- VerifySecp256k1
- HashToCurveTryAndIncrementSecp256k1
- rfc6979nonceSecp256k1
- HashPointsSecp256k1
- GammaToHashSecp256k1
- VerifySecp256k1

## Usage

```shell
skBytes, _ := hex.DecodeString("b920c2c0cf474d02727d7215089d473580943c9e1f6f91d47c3cd025f0d10438")
sk := secp256k1.PrivKeyFromBytes(skBytes)
alpha, _ := hex.DecodeString("73616d706c65")

vrf := Secp256k1Sha256Tai

beta, pi, err := vrf.ProveSecp256k1(sk, alpha)

if err != nil {
  panic(err)
}

compareBeta, err := vrf.VerifySecp256k1(sk.PubKey().ToECDSA(), alpha, pi)
if err != nil {
  panic(err)
}

fmt.Println(beta)
fmt.Println(compareBeta)
```

## Installation 
```shell
go get -u github.com/klayoracle/go-ecvrf
```

## Note

Check [Vechain go-ecvrf Readme](https://github.com/vechain/go-ecvrf) for customization using a different 
cipher suite asides **SECP256K1_SHA256_TAI** or **P256_SHA256_TAI**.

# References

* [draft-irtf-cfrg-vrf-10](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-10.html#nonceP256)
* [go-ecvrf](https://github.com/vechain/go-ecvrf)

# License

Copyright (c) 2020 - 2023 vechain.org.
Copyright (c) 2023 digioracle.link
Licensed under the MIT license.


