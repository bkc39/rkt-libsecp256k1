#lang scribble/manual
@require[@for-label[libsecp256k1 racket/base file/sha1]
         "utils.rkt"]

@title[#:tag "guide"]{Guide}

This guide works through the library by task, one section per task.  Each section ends with
an example program in the package's @filepath{examples} directory that does the same task
end to end; run one with

@commandline{racket -l libsecp256k1/examples/01-sign-verify}

For the full definition of every binding, see the @secref["reference"].

@local-table-of-contents[]

@section[#:tag "guide-keys"]{Keys}

A secret key is an integer in [1, @italic{n}), where @italic{n} is @racket[secp256k1-order],
stored as 32 big-endian bytes.  @racket[generate-secret-key] draws one from the operating
system's random source; @racket[bytes->secret-key] and @racket[integer->secret-key] rebuild a
stored one.  A secret key prints as @litchar{#<secret-key>}, and secret keys are
@racket[equal?] only when they are the same object, so compare their public keys.

The public key, @racket[secret-key->public-key], is safe to share.  Its compressed form is 33
bytes and its uncompressed form 65; @racket[bytes->public-key] reads either.  An integer, or
bytes of the right length, that is not a valid key raises
@racket[exn:fail:libsecp256k1:key]; bytes of another length are a contract violation.  No
error from this library shows the value it was given.

@recorded-examples[guide-keys]

See @filepath{examples/00-keys.rkt}.

@section[#:tag "guide-signing"]{Signing and Verifying}

ECDSA signs a 32-byte digest, not a message: hash the message first, here with
@racket[sha256-bytes].  @racket[ecdsa-sign] takes its nonce from RFC 6979, so the same key and
digest always give the same signature, and it returns only low-S signatures.
@racket[ecdsa-verify] rejects high-S signatures; pass a signature from elsewhere through
@racket[ecdsa-signature-normalize] first.

@recorded-examples[guide-signing]

See @filepath{examples/01-sign-verify.rkt}.

@section[#:tag "guide-recovery"]{Public Key Recovery}

A recoverable signature carries, beside @italic{r} and @italic{s}, a recovery id from 0 to 3
that picks the signer's public key among those the signature and digest allow.
@racket[ecdsa-recover] computes that key, so a signed message need not carry its signer; this
is how Ethereum identifies the sender of a transaction.  Another digest usually recovers
another key rather than failing, so compare the result with the signer you expect.  A
recoverable signature is also a plain one for @racket[ecdsa-verify].

@recorded-examples[guide-recovery]

@filepath{examples/02-recover.rkt} packs a signature as Ethereum's 65 bytes
@italic{r ‖ s ‖ v}, with @italic{v} = 27 + id for an id of 0 or 1, and recovers the signer
from them.  Ethereum signs a Keccak-256 digest; this library takes digests and does not hash.

@section[#:tag "guide-encodings"]{Encodings}

The compact form is 64 bytes, @italic{r ‖ s} as 32-byte big-endian integers; it leaves out a
recoverable signature's id, which is stored beside it.  DER is the variable-length form
Bitcoin uses, at most 72 bytes, and @racket[der->ecdsa-signature] accepts strict DER only.
Compact bytes of the right length that are not a signature, and bytes that are not strict DER,
raise @racket[exn:fail:libsecp256k1:signature]; compact bytes of another length are a contract
violation.

@recorded-examples[guide-encodings]

See @filepath{examples/03-encodings.rkt}.

@section[#:tag "guide-tweaks"]{Tweaks}

Adding a 32-byte tweak @italic{t} to a secret key @italic{k} gives @italic{k + t}; adding it
to the public key @italic{P} gives @italic{P + tG}, the public key of @italic{k + t}.  So
whoever holds only a public key can compute the public keys of children whose secret keys
only its owner can compute.  A tweak not less than @italic{n}, or a result that is zero or the
point at infinity, raises @racket[exn:fail:libsecp256k1:key].

@recorded-examples[guide-tweaks]

@filepath{examples/04-tweaks.rkt} derives numbered children from a parent key and from its
public key, and checks that they agree.
