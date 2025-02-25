---
stand_alone: true
ipr: trust200902
cat: info
submissiontype: IRTF
# area: General [REPLACE]
wg: Internet Engineering Task Force

docname: draft-andersen-hpke-hybrid-kems-latest

title: Post-quantum and Hybrid KEMs for HPKE
# abbrev: Abbreviated Title [REPLACE]
lang: en
kw:
  - hpke
  - hybrid
  - kem
# date: 2025-02-25 -- date is filled in automatically by xml2rfc if not given
author:
- role: editor
  name: Jeff Andersen
  org: Google, LLC
  country: US
  email: jeffandersen@google.com
contributor: # Same structure as author list, but goes into contributors
- name: Chris Fenner
  org: Google, LLC
  email: cfenn@google.com
- name: Jordan Hand
  org: Google, LLC
  email: jhand@google.com

venue:
  group: Crypto Forum
  type: Research Group
  mail: cfrg@ietf.org
  arch: https://mailarchive.ietf.org/arch/search/?email_list=cfrg
  subscribe: https://www.ietf.org/mailman/listinfo/cfrg/
  repo: https://github.com/bluegate010/draft-andersen-hpke-hybrid-kems

normative:
  RFC9180: HPKE
  SP800277ipd:
    title: NIST SP 800-227 (Initial Public Draft) - Recommendations for Key-Encapsulation Mechanisms
    author:
    - name: Gorjan Alagic
    - name: Elaine Barker
    - name: Lily Chen
    - name: Dustin Moody
    - name: Angela Robinson
    - name: Hamilton Silberg
    - name: Noah Waller
  FIPS203:
    title: FIPS 203 - Module-Lattice-Based Key-Encapsulation Mechanism Standard

--- abstract

This memo defines post-quantum and hybrid KEMs for use in Hybrid Public Key Encryption as defined in RFC 9180.

--- middle

# Introduction

{{RFC9180}} defines HPKE, a hybrid asymmetric encryption scheme built on KEMs, KDFs, and AEADs.

{{SP800277ipd}} defines a generic KEM combiner for hybrid KEMs.

This document defines bindings between post-quantum and hybrid KEMs as provided in {{SP800277ipd}} and HPKE as defined in {{RFC9180}}.

## Requirements Language

{::boilerplate bcp14-tagged}

# Post-quantum and hybrid KEMs for HPKE

## ML-DSA-768 use in HPKE

ML-DSA-768 satisfies the HPKE KEM interface as follows.

`SerializePublicKey`, `SerializePrivateKey`, and `DeserializePrivateKey` are the identity functions, as public and private keys are fixed-length byte strings as defined in {{FIPS203}}.

`DeriveKeyPair` is given by

~~~~
def DeriveKeyPair(ikm):
  dkp_prk = HKDF-SHA512-Extract("", ikm)
  dkp_okm = HKDF-SHA512-Expand(dkp_prk, "ml-kem-768-dkp", 64)

  return ML-KEM-768.KeyGen_internal(dkp_okm[0:32], dkp_okm[32:64])
~~~~

`ML-KEM-768.KeyGen_internal` is defined in {{FIPS203}}.

`Encap` is `ML-KEM-768.Encaps(pk)` from {{FIPS203}}, where an ML-KEM encapsulation key check failure causes an HPKE EncapError.

`Decap` is `ML-KEM-768.Decap(ct, sk)` from {{FIPS203}}.

As defined here, ML-DSA-768 is not an authenticated KEM: it does not support `AuthEncap` and `AuthDecap`.

Nsecret, Nenc, Npk, and Nsk are defined in Section 3.

## Hybrid ECDH P-384 + ML-DSA-768 use in HPKE

Hybrid ECDH P-384 + ML-DSA-768 satisfies the HPKE KEM interface as follows.

`SerializePublicKey`, `SerializePrivateKey`, and `DeserializePrivateKey` are the identity functions, as public and private keys are fixed-length byte strings which are concatenations of serialized ECDH keys as defined in {{RFC9180}} and ML-KEM keys as defined in {{FIPS203}}.

`DeriveKeyPair` is given by

~~~~
def DeriveKeyPair(ikm):
  dkp_prk = HKDF-SHA512-Extract("", ikm)
  dkp_okm = HKDF-SHA512-Expand(dkp_prk, "ecdh-p384-ml-kem-768-dkp", 96)

  (pk_ecc, sk_ecc) = DHKEM(P-384, HKDF-SHA384).DeriveKeyPair(dkp_okm[0:32])
  (pk_mlkem, sk_mlkem) = ML-DSA-768.DeriveKeyPair(dkp_okm[32:96])

  return (pk_ecc || pk_mlkem, sk_ecc || sk_mlkem)
~~~~

`DHKEM(P-384, HKDF-SHA384).DeriveKeyPair` is defined in section 7.1.3 of {{RFC9180}}. `ML-DSA-768.DeriveKeyPair` is defined in section 2.1 of this document.

`Encap` is given by

~~~~
def Encap(pk):
  pk_ecc = pk[0:97]
  pk_mlkem = pk[97:1281]

  ss_ecc, ct_ecc = DHKEM(P-384, HKDF-SHA384).Encap(pk_ecc)
  ss_mlkem, ct_mlkem = ML-KEM-768.Encaps(pk_mlkem)

  ss = SHA2-512(ss_ecc || ss_mlkem || ct_ecc || ct_mlkem || pk_ecc || pk_mlkem || 0x0011 || 0x0300)
  ct = ct_ecc || ct_mlkem

  return (ss, ct)
~~~~

`DHKEM(P-384, HKDF-SHA384).Encap` is defined in {{RFC9180}}. `ML-KEM-768.Encaps` is defined in {{FIPS203}}.

0x0011 and 0x0300 are the HPKE KEM identifiers for `DHKEM(P-384, HKDF-SHA384)` and `ML-DSA-768`, respectively.

SHA2-512 is a valid key combiner as given in {{SP800277ipd}}.

An ML-KEM encapsulation key check failure causes an HPKE EncapError.

`Decap` is given by

~~~~
def Decap(ct, sk):
  sk_ecc = sk[0:48]
  sk_mlkem = sk[48:2448]

  ct_ecc = ct[0:97]
  ct_mlkem = ct[97:1185]

  ss_ecc = DHKEM(P-384, HKDF-SHA384).Decap(ct_ecc, sk_ecc)
  ss_mlkem = ML-KEM-768.Decaps(ct_mlkem, sk_mlkem)

  ss = SHA2-512(ss_ecc || ss_mlkem || ct_ecc || ct_mlkem || pk_ecc || pk_mlkem || 0x0011 || 0x0300)

  return ss
~~~~

`DHKEM(P-384, HKDF-SHA384).Decap` is defined in {{RFC9180}}. `ML-KEM-768.Decaps` is defined in {{FIPS203}}.

As defined here, this hybrid scheme is not an authenticated KEM: it does not support `AuthEncap` and `AuthDecap`.

Nsecret, Nenc, Npk, and Nsk are defined in Section 3.

# IANA Considerations {#IANA}

This document requests/registers the following two entries to the "HPKE KEM Identifiers" registry.

   Value:  768 = 0x0300 (please)

   KEM:  ML-KEM-768

   Nsecret:  32

   Nenc:  1088

   Npk:  1184

   Nsk:  2400

   Auth:  no

   Reference:  This document

   Value: 384 + 768 = 1152 = 0x0480 (please)

   KEM: ECDH P-384 + ML-KEM-768

   Nsecret:  64

   Nenc: 1185

   Npk: 1232

   Nsk:  2448

   Auth:  no

   Reference:  This document


# Security Considerations {#Security}

Informally, these KEMs are secure if {{SP800277ipd}} and {{FIPS203}} are secure. This is taken as given.

--- back

# Appendix 1

This becomes an Appendix


# Acknowledgements {#Acknowledgements}
{: numbered="false"}


