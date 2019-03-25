# Silicon

Silicon is another wrapper of Elixir/Erlang crypto packages.

### Installation

The package can be installed by adding `silicon` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:silicon, "~> 0.1.0"}
  ]
end
```

The docs can be found at [https://hexdocs.pm/silicon](https://hexdocs.pm/silicon).

### Packages

We wrapped the packages below:

* `{:libdecaf, "~> 1.0"}` for Ed25519 and SHA3
* `{:keccakf1600, "~> 2.0", hex: :keccakf1600_orig}` for Keccak Origin
* `{:libsecp256k1, "~> 0.1.10"}` for Secp256k1
* `{:blake2_elixir, git: "https://github.com/riverrun/blake2_elixir.git"}` for Blake2b
* `:crypto` for others

### Test Vectors
We added lots of extra test vectors to test against the methods exposed by silicon

#### AES Test Vectors

* AES-CBC: `https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#AES`
* AES-CBC-PKCS7: `https://raw.githubusercontent.com/google/wycheproof/master/testvectors/aes_cbc_pkcs5_test.json`
* AES-GCM: `https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES#GCMVS`
* AES-CTR: Got from `https://github.com/pyca/cryptography`, which is the test vectors from RFC 3686

#### Hash Function Test Vectors

* SHA3: `https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/Secure-Hashing`
* Keccak origin: `https://keccak.team/archives.html` Known-answer and Monte Carlo test results part
* Blake2b: `https://github.com/jedisct1/crypto-test-vectors` and `https://pynacl.readthedocs.io/en/latest/vectors/blake2_vectors/`
* MD5/SHA2: `https://cryptii.com`
* HASH160: `https://bitcoinprices.org/public-key-to-hash/`
* RIPEMD160: `https://www.browserling.com/tools/ripemd160-hash`

#### HMAC Test Vectors

* HMAC_SHA256/SHA512: `https://cryptii.com`

#### Ed25519 Test Vectors

* `https://ed25519.cr.yp.to/python/sign.input`

#### Secp256k1 Test Vectors

* `https://github.com/btccom/secp256k1-go`
* `https://github.com/google/wycheproof/tree/master/testvectors`

