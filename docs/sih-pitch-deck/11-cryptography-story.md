# 11 — The cryptography story

We assess a lot of cryptographic properties. The slide must not look like a textbook.

---

## What we actually assess

TLS version · cipher suite · key-exchange mechanism · forward secrecy · X.509 extraction ·
certificate validity window · public-key algorithm and length · signature algorithm · chain
structure · insecure-configuration checklist · STARTTLS/STLS upgrade integrity · plaintext exposure.

**Twelve properties is too many for a slide.** They must compress.

## The compression: one strip, three groups

```
TRANSPORT          CERTIFICATE              UPGRADE INTEGRITY
TLS version        validity window          STARTTLS / STLS
cipher suite       key algorithm + length   plaintext exposure
key exchange       signature algorithm      insecure configuration
forward secrecy    chain structure
```

Twelve properties, three mental buckets, one line each. A judge parses this in about four seconds.

## The honesty row that must accompany it

The single most important cryptographic message is **not** the property list — it is the
**observability boundary**:

| Property | Observable from passive PCAP? |
|---|---|
| TLS version, cipher, key exchange, forward secrecy | ✅ always (ServerHello is cleartext at every TLS version) |
| X.509 certificate details | ⚠️ **only when TLS ≤1.2 exposes a cleartext handshake** — TLS 1.3 encrypts it (RFC 8446 §2) |
| Certificate **trust** / revocation | ❌ **never** — a PCAP contains no trust anchor (RFC 5280 §6); OCSP/CRL are separate network transactions (RFC 6960) |

This three-row table is worth more slide space than the twelve-property list, because it is the
part no competitor states and the part a technical judge will probe first.

## Recommended slide treatment

- **Slide 3:** the three-group property strip, one line per group. No explanation prose.
- **Slide 4:** the observability boundary, as the first row of the risks/mitigations table.

Splitting it this way means Slide 3 answers *"what does it assess?"* and Slide 4 answers *"and
what can't it?"* — which is exactly what the official pointers on those two slides ask for.

## The single sentence, if space collapses

> **Assesses TLS version, cipher, key exchange and forward secrecy on every session; extracts and
> analyses X.509 certificates wherever the handshake exposes them; and states explicitly where
> passive evidence cannot reach — including certificate trust, which requires an anchor no capture
> contains.**

## Do not

- Do not print cipher-suite hex codes, OIDs, or curve names on a slide.
- Do not say "validates certificates" unqualified (see `DO-NOT-CLAIM.md`).
- Do not imply TLS 1.3 is a weakness — it is correct protocol behaviour that constrains *all*
  passive observers equally.
