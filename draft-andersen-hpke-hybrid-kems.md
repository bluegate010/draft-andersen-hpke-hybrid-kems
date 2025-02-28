---
stand_alone: true
ipr: trust200902
cat: info
submissiontype: IRTF
# area: General [REPLACE]
wg: Internet Engineering Task Force

docname: draft-andersen-hpke-hybrid-kems-latest

title: Hybrid KEMs for HPKE
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
  draft-connolly-cfrg-hpke-mlkem:
    title: ML-KEM for HPKE
    target: https://datatracker.ietf.org/doc/draft-connolly-cfrg-hpke-mlkem

--- abstract

This memo defines hybrid KEMs for use in Hybrid Public Key Encryption as defined in RFC 9180.

--- middle

# Introduction

{{RFC9180}} defines HPKE, a hybrid asymmetric encryption scheme built on KEMs, KDFs, and AEADs.

{{SP800277ipd}} defines a generic KEM combiner for hybrid KEMs.

This document defines bindings between hybrid KEMs as provided in {{SP800277ipd}} and HPKE as defined in {{RFC9180}}.

## Requirements Language

{::boilerplate bcp14-tagged}

# Hybrid KEMs for HPKE

## Hybrid ECDH P-384 + ML-KEM-768 use in HPKE

Hybrid ECDH P-384 + ML-KEM-768 satisfies the HPKE KEM interface as follows.

A helper function `Combiner` is given by

~~~~
def Combiner(ss_ecc, ss_mlkem, ct_ecc, ct_mlkem, pk_ecc, pk_mlkem):
  ss = SHA2-512(ss_ecc || ss_mlkem || ct_ecc || ct_mlkem || pk_ecc || pk_mlkem || 0x0011 || 0x0041)

  return ss
~~~~

0x0011 and 0x0041 are the HPKE KEM identifiers for `DHKEM(P-384, HKDF-SHA384)` and `ML-KEM-768`, respectively. 0x0041 is proposed in {{draft-connolly-cfrg-hpke-mlkem}}.

SHA2-512 is a valid key combiner as given in {{SP800277ipd}}.

`SerializePublicKey`, `SerializePrivateKey`, and `DeserializePrivateKey` are the identity functions, as public and private keys are fixed-length byte strings which are concatenations of serialized ECDH keys as defined in {{RFC9180}} and ML-KEM keys as defined in {{FIPS203}}.

`DeriveKeyPair` is given by

~~~~
def DeriveKeyPair(ikm):
  dkp_prk = HKDF-SHA512-Extract("", ikm)
  dkp_okm = HKDF-SHA512-Expand(dkp_prk, "ecdh-p384-ml-kem-768-dkp", 112)

  (pk_ecc, sk_ecc) = DHKEM(P-384).DeriveKeyPair(dkp_okm[0:48])
  (pk_mlkem, sk_mlkem) = ML-KEM-768.KeyGen_internal(dkp_okm[48:80], dkp_okm[80:112])

  return (pk_ecc || pk_mlkem, sk_ecc || sk_mlkem)
~~~~

`DHKEM(P-384).DeriveKeyPair` is defined in section 7.1.3 of {{RFC9180}}. `ML-KEM-768.KeyGen_internal` is defined in [FIPS203].

`Encap` is given by

~~~~
def Encap(pk):
  pk_ecc = pk[0:97]
  pk_mlkem = pk[97:1281]

  ss_ecc, ct_ecc = DHKEM(P-384, HKDF-SHA384).Encap(pk_ecc)
  ss_mlkem, ct_mlkem = ML-KEM-768.Encaps(pk_mlkem)

  ss = Combiner(ss_ecc, ss_mlkem, ct_ecc, ct_mlkem, pk_ecc, pk_mlkem)
  ct = ct_ecc || ct_mlkem

  return (ss, ct)
~~~~

`DHKEM(P-384, HKDF-SHA384).Encap` is defined in {{RFC9180}}. `ML-KEM-768.Encaps` is defined in {{FIPS203}}.

An ML-KEM encapsulation key check failure causes an HPKE EncapError.

For testing, it is convenient to have a deterministic version
of encapsulation. An implementation of this hybrid scheme MAY provide
the following derandomized function.

~~~
def EncapsulateDerand(pk, encaps_seed):
  pk_ecc = pk[0:97]
  pk_mlkem = pk[97:1281]
  seed_p384 = encaps_seed[0:48]
  seed_mlkem = encaps_seed[48:80]

  (ct_ecc_pub, ct_ecc) = DHKEM(P-384).DeriveKeyPair(seed_p384)

  ss_ecc = DHKEM(P-384).DH(ct_ecc, pk_ecc)
  (ss_mlkem, ct_mlkem) = ML-KEM-768.Encaps_internal(pk_mlkem, seed_mlkem)

  ss = Combiner(ss_ecc, ss_mlkem, ct_ecc, ct_mlkem, pk_ecc, pk_mlkem)
  ct = concat(ct_ecc, ct_mlkem)

  return (ss, ct)
~~~

`pk` is a 1281 byte hybrid encapsulation key which is a concatenation of a serialized ECC public key and an ML-KEM public key. `eseed` MUST be 80 bytes.

`DHKEM(P-384).DH` is the DH group function associated with P-384 as specified in {{RFC9180}}.

`EncapsulateDerand` returns the 64 byte shared secret `ss` and the 1185 byte
ciphertext `ct`.

`Decap` is given by

~~~~
def Decap(ct, sk):
  sk_ecc = sk[0:48]
  sk_mlkem = sk[48:2448]

  ct_ecc = ct[0:97]
  ct_mlkem = ct[97:1185]

  ss_ecc = DHKEM(P-384, HKDF-SHA384).Decap(ct_ecc, sk_ecc)
  ss_mlkem = ML-KEM-768.Decaps(ct_mlkem, sk_mlkem)

  ss = Combiner(ss_ecc, ss_mlkem, ct_ecc, ct_mlkem, pk_ecc, pk_mlkem)

  return ss
~~~~

`DHKEM(P-384, HKDF-SHA384).Decap` is defined in {{RFC9180}}. `ML-KEM-768.Decaps` is defined in {{FIPS203}}.

As defined here, this hybrid scheme is not an authenticated KEM: it does not support `AuthEncap` and `AuthDecap`.

Nsecret, Nenc, Npk, and Nsk are defined in Section 3.

# IANA Considerations {#IANA}

This document requests/registers the following entries to the "HPKE KEM Identifiers" registry.

   Value: 384 + 768 = 1152 = 0x0480 (please)

   KEM: ECDH P-384 + ML-KEM-768

   Nsecret:  64

   Nenc: 1185

   Npk: 1281

   Nsk:  112

   Auth:  no

   Reference:  This document

# Security Considerations {#Security}

Informally, these KEMs are secure if {{SP800277ipd}} and {{FIPS203}} are secure. This is taken as given.

--- back

# Appendix 1

This becomes an Appendix


# Acknowledgements {#Acknowledgements}
{: numbered="false"}


