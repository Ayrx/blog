---
layout: post
title: A DNSSEC Primer
---

DNSSEC is a hugely complex protocol. The current specification is defined in
*three* RFCs: [[RFC4033]], [[RFC4034]] and [[RFC4035]]. This post will attempt
to explain the core of the protocol and what is required to sign a DNS zone
with DNSSEC. The process of validating DNSSEC records shall be left for a
future post.

While there are arguments both for and against DNSSEC, this post will not
take a side. It aims to be a strictly technical explanation on how DNSSEC
works.

# Introduction

The original DNS protocol has no security guarantees. DNS data can be
intercepted, modified and spoofed without any means of detection. The goal of
DNSSEC is to fix this by providing origin authentication and integrity for DNS
data.

The DNS system is organized as a hierarchy of subdomains below the DNS root
domain (`.`). A subdomain and all the subdomains below it that is managed by
one administrative authority is referred to as a DNS zone. As an extension to
DNS, DNSSEC heavily relies on this design for its security model.

# DNSSEC Record Types

DNSSEC introduces four new Resource Record (RR) types to the DNS protocol: DNS
Public Key (DNSKEY), Resource Record Signature (RRSIG), Next Secure (NSEC), and
Delegation Signer (DS).

The use of each RR type will be explained as we walk through the protocol.

# How to sign a zone?

DNSSEC uses a public/private keypair to sign DNS records. The public key
portion of this keypair is stored in a DNSKEY record. This record is used by
resolvers to validate the signatures covering the DNS records of the zone. The
keypair used to sign DNS zone records is referred to as the *Zone Signing Key*
(ZSK). The ZSK is used to sign all records *except* DNSKEY records. Another
public/private keypair, known as the *Key Signing Key* (KSK)  is used to sign
DNSKEY records. This split of responsibilities between the ZSK and KSK allows
for the ZSK to be rotated frequently without changing the KSK. The benefit of
this will become apparent in a later section of this post.

DNS records of the same type are grouped into a RRset which is then signed with
the ZSK. This signature is stored in a RRSIG record which is used by resolvers
to validate the authenticity and integrity of the records contained in the
RRset. In a properly signed DNS zone, there should be a RRSIG record covering
every RR type present in the DNS zone. RRSIG records have an expiration date
(which is distinct from the TTL of the RRSIG record) and RRsets must be
regularly re-signed.

The next piece of the DNSSEC puzzle is NSEC records. NSEC records list the
RRsets associated with the DNS name as well as point to the next authoritative
name and are used to authenticate the denial of existence of a DNS record.
Take the case of a DNS zone beginning at `example.com` with two subdomains,
`alpha.example.com` and `omega.example.com`. The DNS names are sorted in
canonical order (defined in [[RFC4034]] Section 6]) and we end up with the
sorted list [`example.com`, `alpha.example.com`, `omega.example.com`].

`example.com` contains the following NSEC record:

```shell
example.com. 86400 IN NSEC alpha.example.com. (
	A MX RRSIG NSEC )
```

This indicates that `example.com` has a A, MX, RRSIG and NSEC RRset associated
with it and that the next authoritative name in the zone is `alpha.example.com`.

`alpha.example.com` contains the following NSEC record:

```shell
alpha.example.com. 86400 IN NSEC omega.example.com. (
	A MX RRSIG NSEC )
```

This indicates that the next authoritative name in the zone is
`omega.example.com`. We can use this to prove that `beta.example.com` does not
exist since the names are sorted and there are no zones between
`alpha.example.com` and `omega.example.com`.

Unfortunately, NSEC records makes it trivially easy to enumerate the names in
a zone. This is a goldmine of information in a targeted attack since it can
reveal sensitive information about an organization such as technologies in use.
This is the reason why AXFR queries (also known as DNS zone transfers) is
disabled by most DNS servers. NSEC records in DNSSEC have been replaced by
NSEC3 records, which is designed to make enumeration a lot more difficult
(although it does not completely fix the problem). A look at how NSEC3 records
work shall be the topic of a future post.

With all these pieces in place, the integrity of a DNS zone can be verified by
resolvers *if* the resolvers have an out-of-band method to verify the KSK. The
DNSSEC RFCs use the term "island of security" to describe such a zone.
However, this doesn't scale as a DNS resolver cannot possibly verify the
KSK of every domain out of band. DNSSEC solves this by establishing an
authentication chain starting from the root domain (`.`).

Take the example of a DNS zone beginning at `example.com`. `example.com`
contains two DNSKEY records, the ZSK and KSK. `example.com` can establish an
authentication chain to the parent domain (`com`) by publishing a DS record at
`com` containing the hash of the `example.com`'s KSK. Since the DS record is
signed by `com`, any resolver that can validate `com` can validate any child
zones of `com`. This process is repeated between `com` and the root domain
(`.`). With this, any resolver that knows the KSK of the root domain can
validate any DNSSEC enabled domain.

Since the DS record in the parent zone contains the hash of the KSK, rotating
the KSK requires communication with the parent zone, which belongs to a
different administrative authority. This makes the process of rotating the KSK
slightly more difficult. The split of responsibilities between the ZSK and KSK
allows for a much more frequent rotation of the ZSK (which is the key used to
actually sign zone records) since updating the ZSK only requires publishing a
new DNSKEY record. The KSK, which is only used to sign the DNSKEY RRset, can
be kept in a more secure (and more inaccessible) location and can be rotated
less frequently.

# Conclusion

For a zone to be considered properly signed, it should contain:

1. Two DNSKEY records, containing the KSK and ZSK
2. RRSIG records for each RR type in the zone
3. NSEC (or NSEC3) records for each authoritative name in the zone
4. A DS record in the parent zone containing the hash of the KSK

The other side of the DNSSEC protocol is validating the signed zones. That
shall be covered in a future post.

*Shoutout to [@diagprov][diagprov-twitter] for reviewing this post!*

[diagprov-twitter]: https://twitter.com/diagprov
