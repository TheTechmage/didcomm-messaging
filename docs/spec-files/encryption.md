## Security

### Message Encryption

DIDComm Messages are encrypted with the keys of a single DID. A message being sent to multiple DIDs MUST be encrypted for each DID independently. If a single DID has multiple key types, the keys of each type must be used in a separate encryption of the message. 

DIDComm supports two types of message encryption: Authenticated Sender Encryption ("authcrypt") and Anonymous Sender Encryption ("anoncrypt"). Both forms are encrypted to the recipient DID. Only authcrypt provides direct assurances of who the sender is. Each encrypted message MUST use either authcrypt or anoncrypt.

When using JSON encoding, the encrypted form of a JWM is a JWE in General JSON Format. The JOSE family defines [JSON Web Algorithms](https://tools.ietf.org/html/rfc7518) (JWAs) which standardize certain cryptographic operations that are related to preparing JOSE structures.

When using CBOR encoding, the encrypted form is a `COSE_Encrypt` structure as defined in [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052), using the algorithms of [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053). The structure MUST carry its CBOR tag (96). `COSE_Encrypt0` MUST NOT be used: it has no recipients structure, so it offers no place for the ephemeral key, the recipient `kid`, or the wrapped content encryption key that DIDComm key agreement requires. COSE leaves more choices open than JWE (which header map a parameter lives in, whether an algorithm is identified by an integer or a text string, and how an algorithm JOSE defines but COSE does not is carried), so the COSE sections below fix each of those choices; they are normative, so that two independent implementations agree byte for byte.

For the purposes of interoperability, DIDComm messaging does not support all JWAs or COSE algorithms; rather, it takes a subset of the supported algorithms that are applicable for the following cases around secure messaging. These supported algorithms are listed in tables later in the spec.


#### Sender Authenticated Encryption

For an encrypted DIDComm message using JSON encoding, the JWA of [ECDH-1PU](https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-04) MUST be used within the structure of a JWE.

For an encrypted DIDComm message using CBOR encoding, ECDH-1PU MUST be used within the structure of a `COSE_Encrypt`. ECDH-1PU has no COSE registration, so this specification defines its COSE form: the algorithm is identified by the text-string `alg` value `"ECDH-1PU+A256KW"` ([RFC 9052 §3.1](https://www.rfc-editor.org/rfc/rfc9052#section-3.1) permits text-string algorithm identifiers), the shared secret is `Z = Ze || Zs` as in [section 2.1 of the JOSE draft](https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04#section-2.1), and the key-wrapping key is derived with the HKDF-SHA-256 and `COSE_KDF_Context` construction of [RFC 9053 §5.2](https://www.rfc-editor.org/rfc/rfc9053#section-5.2), the same construction COSE uses for `ECDH-ES + A256KW`. The full construction, including where the content authentication tag enters the key derivation, is given in [ECDH-1PU key wrapping and common protected headers](#ecdh-1pu-key-wrapping-and-common-protected-headers).

#### Anonymous Encryption

When a sender would like to encrypt a message for a recipient DID or multiple recipient DIDs but not be authenticated by the recipients, the following SHOULD be used:

- For JSON encoding: the JWA of `ECDH-ES` defined by [RFC 7518](https://tools.ietf.org/html/rfc7518#section-4.6) within the structure of a JWE.
- For CBOR encoding: the COSE algorithm `ECDH-ES + A256KW` (algorithm value `-31`) defined by [RFC 9053 §6.3](https://www.rfc-editor.org/rfc/rfc9053#section-6.3) within the structure of a `COSE_Encrypt`.

Anonymous encryption removes authentication of the sender, which is a significant benefit of DIDComm Messaging; it may make sense, but should only be done thoughtfully, when the context of the use case justifies it. Pairing anonymous encryption with a method of message authentication other than authcrypt as defined in this specification is not generally recommended, as it may have unintended side effects. In particular, a signed message that is anonymously encrypted accomplishes authentication, but loses the repudiability of authcrypt. Further discussion of message authentication can be found in the [DIDComm Guidebook](https://didcomm.org/book/v2).

#### Curves and Content Encryption Algorithms

For the keys involved in key agreement, the first three elliptic curves in this table MUST be supported, and P-521 is optional.

| Curve  | Description                                                  |
| ------ | ------------------------------------------------------------ |
| X25519 | The underlying curve is actually `Curve25519`, however when used in the context of Diffie-Hellman the identifier of `X25519` is used |
| P-384  | NIST defined P-384 elliptic curve                            |
| P-256  | NIST defined P-256 elliptic curve - deprecated in favor of P-384 |
| P-521  | NIST defined P-521 elliptic curve. Optional. |

For content encryption of the message when using JSON encoding, DIDComm inherits the implementation definitions from [JSON Web Algorithms](https://datatracker.ietf.org/doc/html/rfc7518#section-5.1) for AES 256-bit keys. In addition, DIDComm defines optional implementation usage of the draft [XC20P](https://tools.ietf.org/id/draft-amringer-jose-chacha-02.html) algorithm.

For content encryption of the message when using CBOR encoding, DIDComm uses the same algorithms, identified by the COSE `alg` values in the table below. Only `A256GCM` has a registered [COSE algorithm](https://www.iana.org/assignments/cose/cose.xhtml#algorithms) value. COSE registers neither AES-CBC with HMAC ([RFC 9459](https://www.rfc-editor.org/rfc/rfc9459) registers unauthenticated AES-CBC only) nor XChaCha20-Poly1305 (COSE value 24 is ChaCha20-Poly1305 with a 12-byte nonce), so those two are identified by their JWA name as a text-string `alg` value, which [RFC 9052 §3.1](https://www.rfc-editor.org/rfc/rfc9052#section-3.1) permits, and are computed exactly as JWA defines them: `A256CBC-HS512` as in [RFC 7518 §5.2.5](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.5) and `XC20P` as in [draft-amringer-jose-chacha](https://tools.ietf.org/id/draft-amringer-jose-chacha-02.html). In every case the COSE `Enc_structure` is the additional authenticated data, and the authentication tag is appended to the ciphertext in the `ciphertext` field, as COSE does for all AEAD algorithms.

To prevent invalid curve and weak point attacks, implementations that decrypt messages from a NIST curve MUST verify that the received public key (contained in the JWE protected header, or the COSE `ephemeral key` header) is on the curve in question. This check may already be done by some JOSE libraries, but developers should not assume this is the case. See [this explanation](http://blog.intothesymmetry.com/2017/03/critical-vulnerability-in-json-web.html) of the risk, and [this practical guide](https://neilmadden.blog/2017/05/17/so-how-do-you-validate-nist-ecdh-public-keys/) for how to perform the verification correctly. 

| Algorithm | JWA `enc` value | COSE `alg` value | Nonce | Description | Authcrypt/Anoncrypt | Requirements |
| --- | --- | --- | --- | --- | --- | --- |
| A256CBC-HS512 | `"A256CBC-HS512"` | `"A256CBC-HS512"` (text) | 16 bytes | AES256-CBC + HMAC-SHA512 with a 512 bit key | Authcrypt/Anoncrypt | Required |
| A256GCM | `"A256GCM"` | `3` | 12 bytes | AES256-GCM with a 256 bit key | Anoncrypt | Recommended |
| XC20P | `"XC20P"` | `"XC20P"` (text) | 24 bytes | XChaCha20Poly1305 with a 256 bit key | Anoncrypt | Optional |

Implementations MUST choose nonces securely. The nonce is the JWE `iv` or the COSE `IV` header (label 5).

#### Key Wrapping Algorithms

##### JSON Encoding (JWA)

| KW Algorithm    | Curve (epk crv) | key type (epk kty) | Description                                                  |
| --------------- | --------------- | ------------------ | ------------------------------------------------------------ |
| ECDH-ES+A256KW  | P-256           | EC                 | ECDH-ES key wrapping using key with NIST defined P-256 elliptic curve to create a 256 bits key as defined in [RFC 7518](https://tools.ietf.org/html/rfc7518#section-4.6.2)                                                                                  |
| ECDH-ES+A256KW  | P-384           | EC                 | ECDH-ES key wrapping using key with NIST defined P-384 elliptic curve to create a 256 bits key as defined in [RFC 7518](https://tools.ietf.org/html/rfc7518#section-4.6.2)                                                                                  |
| ECDH-ES+A256KW  | P-521           | EC                 | ECDH-ES key wrapping using key with NIST defined P-521 elliptic curve to create a 512 bits key as defined in [RFC 7518](https://tools.ietf.org/html/rfc7518#section-4.6.2)                                                                                  |
| ECDH-ES+A256KW  | X25519          | OKP                | ECDH-ES with X25519 ([RFC 7748 section 5](https://tools.ietf.org/html/rfc7748#section-5)) to create a 256 bits key. The underlying curve is actually `Curve25519`, however when used in the context of Diffie-Hellman the identifier of `X25519` is used |
| ECDH-1PU+A256KW | P-256           | EC                 | ECDH-1PU key wrapping using key with NIST defined P-256 elliptic curve to create a 256 bits key as defined in [ECDH-1PU](https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-04#section-2) |
| ECDH-1PU+A256KW | P-384           | EC                 | ECDH-1PU key wrapping using key with NIST defined P-384 elliptic curve to create a 256 bits key as defined in [ECDH-1PU](https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-04#section-2) |
| ECDH-1PU+A256KW | P-521           | EC                 | ECDH-1PU key wrapping using key with NIST defined P-521 elliptic curve to create a 512 bits key as defined in [ECDH-1PU](https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-04#section-2) |
| ECDH-1PU+A256KW | X25519          | OKP                | ECDH-1PU X25519 ([RFC7748 section 5](https://tools.ietf.org/html/rfc7748#section-5)) to create a 256 bits key as defined in [ECDH-1PU](https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-04#section-2) |

##### CBOR Encoding (COSE)

The `ephemeral key` is a `COSE_Key` ([RFC 9052 §7](https://www.rfc-editor.org/rfc/rfc9052#section-7)) of the key type and curve shown; `kty` and `crv` are given with their registered integer values. For EC2 keys, receivers MUST accept the `y` coordinate in either form [RFC 9053 §7.1.1](https://www.rfc-editor.org/rfc/rfc9053#section-7.1.1) allows (a byte string, or the compressed-point boolean).

| KW Algorithm    | COSE `alg` value | Curve (`ephemeral key` crv) | key type (`ephemeral key` kty) | Description                                                  |
| --------------- | ---------------- | --------------------------- | ------------------------------ | ------------------------------------------------------------ |
| ECDH-ES+A256KW  | `-31`            | P-256 (`1`)                 | EC2 (`2`)                      | ECDH-ES key wrapping using key with NIST defined P-256 elliptic curve to create a 256 bits key as defined in [RFC 9053 §6.3](https://www.rfc-editor.org/rfc/rfc9053#section-6.3) |
| ECDH-ES+A256KW  | `-31`            | P-384 (`2`)                 | EC2 (`2`)                      | ECDH-ES key wrapping using key with NIST defined P-384 elliptic curve to create a 256 bits key as defined in [RFC 9053 §6.3](https://www.rfc-editor.org/rfc/rfc9053#section-6.3) |
| ECDH-ES+A256KW  | `-31`            | P-521 (`3`)                 | EC2 (`2`)                      | ECDH-ES key wrapping using key with NIST defined P-521 elliptic curve to create a 512 bits key as defined in [RFC 9053 §6.3](https://www.rfc-editor.org/rfc/rfc9053#section-6.3) |
| ECDH-ES+A256KW  | `-31`            | X25519 (`4`)                | OKP (`1`)                      | ECDH-ES with X25519 ([RFC 7748 section 5](https://tools.ietf.org/html/rfc7748#section-5)) to create a 256 bits key. The underlying curve is actually `Curve25519`, however when used in the context of Diffie-Hellman the identifier of `X25519` is used |
| ECDH-1PU+A256KW | `"ECDH-1PU+A256KW"` (text) | P-256 (`1`)        | EC2 (`2`)                      | ECDH-1PU key wrapping using key with NIST defined P-256 elliptic curve to create a 256 bits key as defined in [ECDH-1PU key wrapping and common protected headers](#ecdh-1pu-key-wrapping-and-common-protected-headers) |
| ECDH-1PU+A256KW | `"ECDH-1PU+A256KW"` (text) | P-384 (`2`)        | EC2 (`2`)                      | ECDH-1PU key wrapping using key with NIST defined P-384 elliptic curve to create a 256 bits key as defined in [ECDH-1PU key wrapping and common protected headers](#ecdh-1pu-key-wrapping-and-common-protected-headers) |
| ECDH-1PU+A256KW | `"ECDH-1PU+A256KW"` (text) | P-521 (`3`)        | EC2 (`2`)                      | ECDH-1PU key wrapping using key with NIST defined P-521 elliptic curve to create a 512 bits key as defined in [ECDH-1PU key wrapping and common protected headers](#ecdh-1pu-key-wrapping-and-common-protected-headers) |
| ECDH-1PU+A256KW | `"ECDH-1PU+A256KW"` (text) | X25519 (`4`)       | OKP (`1`)                      | ECDH-1PU X25519 ([RFC7748 section 5](https://tools.ietf.org/html/rfc7748#section-5)) to create a 256 bits key as defined in [ECDH-1PU key wrapping and common protected headers](#ecdh-1pu-key-wrapping-and-common-protected-headers) |

#### Perfect Forward Secrecy

The mapping of the Perfect Forward Secrecy concepts to DIDComm requires some discussion, due to the lack of a session construct. Please refer to the [DIDComm Guidebook](https://didcomm.org/book/v2/pfs) for details.

#### Man in the Middle

DIDComm Messaging's guarantees with respect to man-in-the-middle attacks are easily misunderstood, since DIDs rather than human identity are the concern of the algorithm. Please refer to the [DIDComm Guidebook](https://didcomm.org/book/v2/mitm) for details.

#### Key IDs

Keys used by DIDComm envelopes will probably be sourced from the DIDs exchanged between two agents. Specifically, both sender and recipient encryption keys are usually  retrieved from the respective DID document's `keyAgreement` verification section as per the [DID Document Keys](https://identity.foundation/didcomm-messaging/spec/#did-document-keys) definition.

When Alice is preparing an envelope intended for Bob, the packing process should use a key from both hers and Bob's DID document's `keyAgreement` section.

Assuming Alice has a DID document with the following `keyAgreement` definition (source: [DID V1 Example 17](https://www.w3.org/TR/did-core/#example-17-key-agreement-property-containing-two-verification-methods)):
```jsonc
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:example:123456789abcdefghi",
  ...
  "keyAgreement": [
    // this method can be used to perform key agreement as did:...fghi
    "did:example:123456789abcdefghi#keys-1",
    // this method is *only* approved for key agreement usage, it will not
    // be used for any other verification relationship, so its full description is
    // embedded here rather than using only a reference
    {
      "id": "did:example:123#zC9ByQ8aJs8vrNXyDhPHHNNMSHPcaSgNpjjsBYpMMjsTdS",
      "type": "X25519KeyAgreementKey2019", // external (property value)
      "controller": "did:example:123",
      "publicKeyBase58": "9hFgmPVfmBZwRvFEyniQDBkz9LmV7gDEqytWyGZLmDXE"
    }
  ],
  ...
}
```

The envelope packing process would set the `skid` header with value `did:example:123456789abcdefghi#keys-1` in the envelope's protected headers and fetch the underlying key to execute ECDH-1PU key derivation for content key wrapping.

Assuming she also has Bob's DID document which happens to include the following `keyAgreement` section:

```jsonc
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:example:jklmnopqrstuvwxyz1",
  ...
  "keyAgreement": [
    {
      "id": "did:example:jklmnopqrstuvwxyz1#key-1",
      "type": "X25519KeyAgreementKey2019", // external (property value)
      "controller": "did:example:jklmnopqrstuvwxyz1",
      "publicKeyBase58": "9hFgmPVfmBZwRvFEyniQDBkz9LmV7gDEqytWyGZLmDXE"
    }
  ],
  ...
}
```

Unless previously coordinated in a layer above DIDComm, the default recipients of the envelope SHOULD include all the `keyAgreement` entries representing Bob. This allows Bob to decrypt his messages on any device he controls, without sharing keys across his devices. The corresponding `kid` header for this recipient MUST have a DID URL pointing to a corresponding verification method in the DID document. This verification method MUST be associated with the `keyAgreement` verification relationship and the verification material MUST be retrieved from the DID document to execute the ECDH-1PU key derivation for content key wrapping.

When Bob receives the envelope, the unpacking process on his end resolves the `skid` protected header value using Alice's DID document's `keyAgreement[0]` in order to extract her public key. In Alice's DID document example above, `keyAgreement[0]` is a reference id. It would be resolved from the main `verificationMethod[]` of Alice's DID document (not shown in the example).

Once resolved, the unpacker will then execute ECDH-1PU key derivation using this key and Bob's own recipient key found in the envelope's `recipients[0]` to unwrap the content encryption key.

#### Protecting the Sender Identity

When employing authenticated encryption, the header of the encrypted message envelope must necessarily reveal the key identifier used by the sender of the message (the `skid`). This is used by recipients to resolve the sender's public key material in order to decrypt the message. In the case of communication between two public DIDs, this may allow outside parties to directly correlate the sender of an encrypted message to a known identity.

If two communicating parties establish single-purpose DIDs (e.g., peer DIDs) for secure communication, then the correlation to any publicly known identities may be limited, although multiple messages referencing the same DIDs will still provide an opportunity for correlation.

A layer of anonymous encryption (employing ECDH-ES) may be applied around an authenticated encryption envelope (employing ECDH-1PU), obscuring the sender's identity for all but the recipient of the inner envelope. In the case of a message forwarded via mediators, anonymous encryption is automatic.

#### ECDH-1PU key wrapping and common protected headers

##### JSON Encoding (JWE)

When using authcrypt with JSON encoding, the 1PU draft [mandates](https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04#section-2.1) the use of the AES_CBC_HMAC_SHA family of content encryption algorithms. To meet this requirement, JWE messages MUST use common `epk`, `apu`, `apv` and `alg` headers for all recipient keys. They MUST be set in the `protected` JWE section.

As per this requirement, the JWE building must first encrypt the payload, then use the resulting `tag` as part of the key derivation process when wrapping the `cek`.

To meet this requirement, the above headers are defined as follows:

* `epk`: generated once for all recipient keys. It MUST be of the same type and curve as all recipient keys since kdf with the sender key must be on the same curve.
  - Example: `"epk": {"kty": "EC","crv": "P-256","x": "BVDo69QfyXAdl6fbK6-QBYIsxv0CsNMtuDDVpMKgDYs","y": "G6bdoO2xblPHrKsAhef1dumrc0sChwyg7yTtTcfygHA"}`
* `apu`: similar to `skid`, this is the producer (sender) identifier, it MUST contain the `skid` value base64 RawURL (no padding) encoded. Note: this is base64URL(`skid` value).
  - Example for `skid` mentioned in an earlier [section](#key-ids-kid-and-skid-headers-references-in-the-did-document) above: `ZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleXMtMQ`
* `apv`: this represents the recipients' `kid` list. The list must be alphanumerically sorted, `kid` values will then be concatenated with a `.` and the final result MUST be base64 URL (no padding) encoding of the SHA256 hash of concatenated list.
* `alg`: this is the key wrapping algorithm, ie: `ECDH-1PU+A256KW`.

Even though `apu`/`apv` are not mandatory JWE recipients headers, they are required in this specification to authenticate the sender via the ECDH-1PU key wrapping algorithm.

A final note about `skid` header: since the 1PU draft [does not require](https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04#section-2.2.1) this header, authcrypt implementations MUST be able to resolve the sender kid from the `apu` header if `skid` is not set.

##### CBOR Encoding (COSE)

When using authcrypt with CBOR encoding, the same requirements apply, expressed in COSE's layered headers. A `COSE_Encrypt` has one pair of header maps for the body and one pair for each recipient, so where JWE puts the common key-agreement headers in its single `protected` header, COSE puts them in each recipient's protected header, which the key derivation then binds. The headers MUST be placed as follows.

**Body protected header** (bound into the `Enc_structure`, and so into the content encryption):

* `alg` (label 1): the content encryption algorithm, e.g. `"A256CBC-HS512"`.
* `typ` (label 16, [RFC 9596](https://www.rfc-editor.org/rfc/rfc9596)): the media type, `application/didcomm-encrypted+cbor`.

**Body unprotected header**:

* `IV` (label 5): the content encryption nonce.

**Recipient protected header**, which MUST be byte-for-byte identical for every recipient (the COSE form of JWE's common `epk`, `apu`, `apv` and `alg` headers for all recipient keys):

* `alg` (label 1): equivalent to JWE's `alg`, the key wrapping algorithm: `"ECDH-1PU+A256KW"`.
* `ephemeral key` (label -1): equivalent to JWE's `epk`, a `COSE_Key` generated once for all recipient keys. It MUST be of the same type and curve as all recipient keys since kdf with the sender key must be on the same curve.
* `PartyU identity` (label -21): equivalent to JWE's `apu`: the sender's `kid` (the `skid` value) as a UTF-8 byte string. JWE base64url-encodes this value because its headers are text; COSE carries the bytes directly.
* `PartyV identity` (label -24): equivalent to JWE's `apv`: the SHA256 hash, as a 32-byte string, of the alphanumerically sorted recipient `kid` list concatenated with `.` &mdash; exactly the bytes JWE base64url-encodes.

**Recipient unprotected header**:

* `kid` (label 4): the recipient's `kid`, a DID URL, as a UTF-8 byte string; equivalent to the JWE per-recipient `kid` header.

The `static key id` header (label -3, JWE's `skid`) MAY be omitted, since it would repeat `PartyU identity` byte for byte. As with JWE, implementations MUST be able to resolve the sender `kid` from `PartyU identity` when it is absent.

As per the 1PU requirement, the `COSE_Encrypt` building must first encrypt the payload, then use the resulting authentication tag (the final bytes of the body `ciphertext`) as part of the key derivation process when wrapping the `cek`. The shared secret is `Z = Ze || Zs`, where `Ze` is the ECDH output of the ephemeral key and the recipient key and `Zs` that of the sender's static key and the recipient key. The key-wrapping key is `HKDF-SHA-256(IKM = Z, salt = empty, info = COSE_KDF_Context, L = 256 bits)`, where the `COSE_KDF_Context` of [RFC 9053 §5.2](https://www.rfc-editor.org/rfc/rfc9053#section-5.2) is:

```
COSE_KDF_Context = [
  AlgorithmID : -5,                              ; A256KW: the algorithm the derived key is used with
  PartyUInfo  : [ <PartyU identity>, nil, nil ],
  PartyVInfo  : [ <PartyV identity>, nil, nil ],
  SuppPubInfo : [ 256, <recipient protected header>, <tag> ]
]
```

`PartyUInfo` and `PartyVInfo` carry the same byte strings as the recipient protected header, with `nil` for `nonce` and `other`. `SuppPubInfo` holds the derived key length in bits, the recipient's protected header exactly as serialized in the message, and, in its `other` field, the content authentication tag. No `salt` header (label -20) is sent. The derived key wraps the `cek` with AES-256 key wrap ([RFC 3394](https://www.rfc-editor.org/rfc/rfc3394)); the result is the recipient's `ciphertext` field.

#### ECDH-ES key wrapping and common protected headers

##### JSON Encoding (JWE)

When using anoncrypt with JSON encoding, any of the valid content encryption algorithms may be used. To meet this requirement, JWE messages MUST use common `epk`, `apv` and `alg` headers for all recipient keys. They MUST be set in the `protected` JWE section.

As per this requirement, the JWE building must first encrypt the payload, then use the resulting `tag` as part of the key derivation process when wrapping the `cek`.

To meet this requirement, the above headers are defined as follows:

* `epk`: generated once for all recipient keys. It MUST be of the same type and curve as all recipient keys since kdf with the sender key must be on the same curve.
  - Example: `"epk": {"kty": "EC","crv": "P-256","x": "BVDo69QfyXAdl6fbK6-QBYIsxv0CsNMtuDDVpMKgDYs","y": "G6bdoO2xblPHrKsAhef1dumrc0sChwyg7yTtTcfygHA"}`
* `apv`: this represents the recipients' `kid` list. The list must be alphanumerically sorted, `kid` values will then be concatenated with a `.` and the final result MUST be base64 URL (no padding) encoding of the SHA256 hash of concatenated list. 
* `alg`: this is the key wrapping algorithm, ie: `ECDH-ES+A256KW`.

Note: `apu` will not be present when using ECDH-ES.

##### CBOR Encoding (COSE)

When using anoncrypt with CBOR encoding, the headers are placed as for authcrypt above, with these differences:

* The recipient protected header's `alg` (label 1) is `-31` (`ECDH-ES + A256KW`), and `PartyU identity` is not present.
* The body protected header's `alg` is any of the valid content encryption algorithms.
* `static key id` is never present.

The key derivation is that of `ECDH-ES + A256KW` in [RFC 9053 §6.3](https://www.rfc-editor.org/rfc/rfc9053#section-6.3): `Z` is the ECDH output of the ephemeral key and the recipient key alone, and the `COSE_KDF_Context` is as above with a `PartyUInfo` of `[nil, nil, nil]` and no `other` field in `SuppPubInfo` (the content tag is not bound into the key derivation).

#### Examples

While the details of encrypting a JWM into a JWE are included in the [JWM spec](https://tools.ietf.org/html/draft-looker-jwm-01), a few examples are included here for clarity. See section [Appendix C.3](#c3-didcomm-encrypted-messages).

For CBOR encoding, the equivalent `COSE_Encrypt` structures are used, laid out as described above.

##### CBOR Encoding Considerations

When implementing CBOR encoding for DIDComm messages, the following considerations should be taken into account:

1. COSE structures use a more compact representation than JWE, which can significantly reduce message size.
2. COSE uses integer labels for header parameters instead of string keys, further reducing size.
3. When converting between JSON and CBOR representations, care must be taken to ensure all security properties are preserved.
4. Implementations should provide clear error messages when encountering encoding issues to aid in debugging.

TODO: Add specific examples of CBOR-encoded DIDComm messages in the appendix.
