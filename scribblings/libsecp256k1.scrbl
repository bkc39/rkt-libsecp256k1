#lang scribble/manual
@require[@for-label[libsecp256k1 racket/base racket/contract file/sha1]
         scribble/example]
@(define secp-eval (make-base-eval '(require libsecp256k1 file/sha1)))

@title{libsecp256k1: secp256k1 Keys and ECDSA Signatures}
@author{bkc}
@defmodule[libsecp256k1]

FFI bindings to Bitcoin Core's
@hyperlink["https://github.com/bitcoin-core/secp256k1"]{libsecp256k1} C library: secret
and public keys on the secp256k1 curve, deterministic ECDSA signatures, public key
recovery and key tweaks.  This is not the pure-Racket @tt{secp256k1} package.

@bold{License.} This package is distributed under @bold{Apache-2.0 OR MIT}; the bundled
libsecp256k1 source is distributed under @bold{MIT}.

@bold{Acknowledgements.} The libsecp256k1 contributors.

@bold{AI Disclosure.} This package and its documentation were created with the use of AI
tools.

@table-of-contents[]

@section{Secret Keys}

@defproc[(secret-key? [v any/c]) boolean?]{
Recognizes secret keys.}

@defproc[(generate-secret-key) secret-key?]{
A fresh key from the operating system's random source.}

@defproc[(bytes->secret-key [bs secret-bytes/c]) secret-key?]{
The key whose big-endian value is @racket[bs].  Raises @racket[exn:fail:libsecp256k1:key]
when the value is zero or not less than @racket[secp256k1-order].  A secret key prints as
@litchar{#<secret-key>}, and errors never show it or the bytes it came from.

@examples[#:eval secp-eval
  (define one (bytes->secret-key (bytes-append (make-bytes 31 0) #"\1")))
  one
  (eval:error (bytes->secret-key (make-bytes 32 0)))]}

@defproc[(secret-key->bytes [key secret-key/c]) bytes?]{
A fresh, mutable 32-byte copy.}

@defproc[(secret-key->public-key [key secret-key/c]) public-key?]{
The public key @italic{kG}.}

@defproc[(secret-key-negate [key secret-key/c]) secret-key?]{
The key @italic{n − k}.}

@deftogether[(@defthing[secret-bytes/c flat-contract?]
              @defthing[secret-key/c flat-contract?])]{
32 bytes, and secret keys.  A violation names the kind and length of the value it was given,
never the value.}

Keys are never printed.  Racket's memory manager may copy key bytes, so this library cannot
erase them from memory.

@section{Public Keys}

@defproc[(public-key? [v any/c]) boolean?]{
Public keys are @racket[equal?] when they are the same point.}

@defproc[(bytes->public-key [bs public-key-bytes/c]) public-key?]{
Parses the compressed form (33 bytes, prefix @tt{02} or @tt{03}) or the uncompressed form
(65 bytes, prefix @tt{04}).  Raises @racket[exn:fail:libsecp256k1:key] for any other prefix
or for bytes that are not a point on the curve.}

@defproc[(public-key->bytes [key public-key?] [#:compressed? compressed? any/c #t]) bytes?]{
The compressed or uncompressed form.

@examples[#:eval secp-eval
  (define pk (secret-key->public-key one))
  pk
  (bytes->hex-string (public-key->bytes pk #:compressed? #f))
  (equal? pk (bytes->public-key (public-key->bytes pk #:compressed? #f)))]}

@defproc[(public-key-negate [key public-key?]) public-key?]{
The point @italic{−P}.}

@defproc[(public-key-combine [key public-key?] ...+) public-key?]{
The sum.  Raises @racket[exn:fail:libsecp256k1:key] when it is the point at infinity.}

@defthing[public-key-bytes/c flat-contract?]{
33 or 65 bytes.}

@section{ECDSA Signatures}

Arguments come in the C library's order: the digest before the key, and the signature first.

@defthing[secp256k1-order exact-positive-integer?]{
The curve order @italic{n}.}

@deftogether[(@defthing[digest/c flat-contract?]
              @defthing[scalar/c flat-contract?]
              @defthing[recovery-id/c flat-contract?]
              @defthing[compact-bytes/c flat-contract?])]{
32 bytes; an integer in [0, @italic{n}); an integer in [0, 3]; 64 bytes.}

@deftogether[(@defproc[(ecdsa-signature [r scalar/c] [s scalar/c]) ecdsa-signature?]
              @defproc[(ecdsa-signature? [v any/c]) boolean?]
              @defproc[(ecdsa-signature-r [sig ecdsa-signature?]) scalar/c]
              @defproc[(ecdsa-signature-s [sig ecdsa-signature?]) scalar/c])]{
A signature @italic{(r, s)}.  Signatures are @racket[equal?] when they are the same kind and
their fields are equal.}

@defproc[(ecdsa-sign [digest digest/c] [key secret-key/c]) ecdsa-signature?]{
Signs a 32-byte digest.  The caller hashes the message.  The nonce comes from RFC 6979, so
the same key and digest always give the same signature, and @racket[s] is always in the lower
half of the order.

@examples[#:eval secp-eval
  (define digest (sha256-bytes #"Satoshi Nakamoto"))
  (define sig (ecdsa-sign digest one))
  sig
  (ecdsa-verify sig digest pk)]}

@defproc[(ecdsa-verify [sig ecdsa-signature?] [digest digest/c] [key public-key?]) boolean?]{
Rejects signatures whose @racket[s] is in the upper half of the order.  Use
@racket[ecdsa-signature-normalize] first to accept them.}

@deftogether[(@defproc[(ecdsa-signature-low-s? [sig ecdsa-signature?]) boolean?]
              @defproc[(ecdsa-signature-normalize [sig ecdsa-signature?]) ecdsa-signature?])]{
Whether @racket[s] is in the lower half of the order, and the signature with @italic{n − s}
in place of a high @racket[s].  Normalizing keeps the kind; a recoverable signature's
recovery id changes with @racket[s], so recovery gives the same key.

@examples[#:eval secp-eval
  (define high (ecdsa-signature (ecdsa-signature-r sig)
                                (- secp256k1-order (ecdsa-signature-s sig))))
  (ecdsa-verify high digest pk)
  (equal? (ecdsa-signature-normalize high) sig)]}

@subsection{Encodings}

Compact is @italic{r ‖ s} as 32-byte big-endian integers; DER is strict.  Parsing raises
@racket[exn:fail:libsecp256k1:signature].

@deftogether[(@defproc[(ecdsa-signature->compact [sig ecdsa-signature?]) compact-bytes/c]
              @defproc[(compact->ecdsa-signature
                        [bs compact-bytes/c]
                        [#:recovery-id id (or/c #f recovery-id/c) #f])
                       ecdsa-signature?])]{
With @racket[id], the result is an @racket[ecdsa-recoverable-signature?].}

@deftogether[(@defproc[(ecdsa-signature->der [sig ecdsa-signature?]) bytes?]
              @defproc[(der->ecdsa-signature [bs bytes?]) ecdsa-signature?])]{
@examples[#:eval secp-eval
  (bytes->hex-string (ecdsa-signature->der sig))
  (equal? (der->ecdsa-signature (ecdsa-signature->der sig)) sig)]}

@subsection{Public Key Recovery}

@deftogether[(@defproc[(ecdsa-recoverable-signature [r scalar/c] [s scalar/c]
                                                    [id recovery-id/c])
                       ecdsa-recoverable-signature?]
              @defproc[(ecdsa-recoverable-signature? [v any/c]) boolean?]
              @defproc[(ecdsa-recoverable-signature-recovery-id
                        [sig ecdsa-recoverable-signature?])
                       recovery-id/c])]{
A signature together with the recovery id that selects its signer among up to four
candidates.  It is also an @racket[ecdsa-signature?].}

@defproc[(ecdsa-sign-recoverable [digest digest/c] [key secret-key/c])
         ecdsa-recoverable-signature?]{
Signs as @racket[ecdsa-sign] does, with the same @racket[r] and @racket[s].}

@defproc[(ecdsa-recover [sig ecdsa-recoverable-signature?] [digest digest/c])
         (or/c public-key? #f)]{
@racket[#f] when no public key recovers.

@examples[#:eval secp-eval
  (define rsig (ecdsa-sign-recoverable digest one))
  (ecdsa-recoverable-signature-recovery-id rsig)
  (equal? (ecdsa-recover rsig digest) pk)]}

@section{Tweaks}

@deftogether[(@defproc[(secret-key-tweak-add [key secret-key/c] [tweak secret-bytes/c])
                       secret-key?]
              @defproc[(public-key-tweak-add [key public-key?] [tweak secret-bytes/c])
                       public-key?])]{
Add @racket[tweak], read as a big-endian integer, to the key: @italic{k + t} and
@italic{P + tG} respectively.  Raise @racket[exn:fail:libsecp256k1:key] when the tweak is not
less than the order or the result is zero or the point at infinity.

@examples[#:eval secp-eval
  (define t (bytes-append (make-bytes 31 0) #"\1"))
  (secret-key->public-key (secret-key-tweak-add one t))
  (equal? (public-key-tweak-add pk t) (secret-key->public-key (secret-key-tweak-add one t)))]}

@section{Errors}

Contract violations are ordinary @racket[exn:fail:contract:blame] errors.

@defstruct*[(exn:fail:libsecp256k1 exn:fail) ()]{
The parent of this library's exceptions.}

@defstruct*[(exn:fail:libsecp256k1:load exn:fail:libsecp256k1) ()]{
Raised by every procedure that needs the C library when no usable library was found.}

@defstruct*[(exn:fail:libsecp256k1:key exn:fail:libsecp256k1) ()]{
Raised for an invalid secret or public key, tweak or sum.}

@defstruct*[(exn:fail:libsecp256k1:signature exn:fail:libsecp256k1) ()]{
Raised when compact or DER bytes are not a valid signature.}

@defstruct*[(exn:fail:libsecp256k1:illegal-argument exn:fail:libsecp256k1) ()]{
Raised when the C library reports an illegal argument, which this library's procedures never
pass.}

@defstruct*[(exn:fail:libsecp256k1:internal exn:fail:libsecp256k1) ()]{
Raised when the C library reports an internal error.}

@section{The C Library}

@defproc[(libsecp256k1-origin) (or/c 'bundled 'system 'environment)]{
Which libsecp256k1 is in use.  @racket['bundled] means the copy compiled when the package was
installed; @racket['system] means the operating system's @tt{libsecp256k1} (0.2 or later, with
the recovery module), used when the package could not compile its own; @racket['environment]
means the file named by the @tt{LIBSECP256K1_LIBRARY} environment variable.  If that variable
is @tt{system}, only the system library is used.  Raises
@racket[exn:fail:libsecp256k1:load] when none can be loaded; every other procedure that needs
the C library raises it too.}

Every procedure may be called from any thread or place.
