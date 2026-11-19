#lang scribble/manual
@require[@for-label[libsecp256k1 racket/base racket/contract file/sha1]]

@title{libsecp256k1: secp256k1 Keys and ECDSA Signatures}
@author{bkc}
@defmodule[libsecp256k1]

FFI bindings to Bitcoin Core's
@hyperlink["https://github.com/bitcoin-core/secp256k1"]{libsecp256k1} C library: secret
and public keys on the secp256k1 curve, deterministic ECDSA signatures, public key
recovery and key tweaks.  This is not the pure-Racket @tt{secp256k1} package.

This manual has two parts: the @secref["guide"] works through the library by task, and the
@secref["reference"] documents every binding.

@bold{Security.} A secret key prints as @litchar{#<secret-key>}.  No error from this
library shows an argument: a contract violation, a wrong argument count or an unknown
keyword names what was expected and the kind and length of what was given, never the value.
The named contracts keep that guarantee only inside this library; @racket[secret-bytes/c]
in a caller's own @racket[->] contract prints the value like any other contract.  Racket's
memory manager may copy key bytes, so this library cannot erase them from memory.

@bold{Installation.} The package ships a prebuilt libsecp256k1 0.8.0 for x86_64 Linux
(glibc 2.17 or later) and Apple-silicon macOS only, and installing copies it into place;
nothing is compiled.  On every other platform, including ARM Linux, Intel macOS and Windows,
install the operating system's libsecp256k1 0.2 or later, built with the recovery module, or
name a library file with @tt{LIBSECP256K1_LIBRARY}; see @racket[libsecp256k1-origin].

@bold{License.} This package is distributed under @bold{Apache-2.0 OR MIT}; the bundled
libsecp256k1 library is distributed under @bold{MIT}, with its notice in
@filepath{native-libs/LICENSE.libsecp256k1}.

@bold{Acknowledgements.} The libsecp256k1 contributors.

@bold{AI Disclosure.} This package and its documentation were created with the use of AI
tools.

@table-of-contents[]

@include-section["guide.scrbl"]
@include-section["reference.scrbl"]
