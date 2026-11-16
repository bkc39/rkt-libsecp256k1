#lang racket/base

(provide manual-examples)

(define manual-examples
  (quote-syntax
   ((secret-keys
     [(define one (integer->secret-key 1))]
     [one "#<secret-key>"]
     [(secret-key->integer one) "1"]
     [(equal? one (integer->secret-key 1)) "#f"]
     [(integer->secret-key 0)
      (error "integer->secret-key: invalid secret key;
 the value is less than 1 or not less than the curve order")])
    (public-keys
     [(define pk (secret-key->public-key one))]
     [pk ("#<public-key"
          " 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798>")]
     [(bytes->hex-string (public-key->bytes pk #:compressed? #f))
      ("\"0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
       "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8\"")]
     [(equal? pk (bytes->public-key (public-key->bytes pk #:compressed? #f))) "#t"])
    (signing
     [(define digest (sha256-bytes #"Satoshi Nakamoto"))]
     [(define sig (ecdsa-sign digest one))]
     [sig
      ("#<ecdsa-signature 934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8"
       "2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5>")]
     [(ecdsa-verify sig digest pk) "#t"])
    (normalizing
     [(define high (ecdsa-signature (ecdsa-signature-r sig)
                                    (- secp256k1-order (ecdsa-signature-s sig))))]
     [(ecdsa-verify high digest pk) "#f"]
     [(equal? (ecdsa-signature-normalize high) sig) "#t"])
    (der
     [(bytes->hex-string (ecdsa-signature->der sig))
      ("\"3045022100934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8"
       "02202442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5\"")]
     [(equal? (der->ecdsa-signature (ecdsa-signature->der sig)) sig) "#t"])
    (recovery
     [(define rsig (ecdsa-sign-recoverable digest one))]
     [rsig
      ("#<ecdsa-recoverable-signature"
       " 934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8"
       "2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5 id=1>")]
     [(equal? (ecdsa-recover rsig digest) pk) "#t"])
    (tweaks
     [(define t (secret-key->bytes one))]
     [(secret-key->public-key (secret-key-tweak-add one t))
      ("#<public-key"
       " 02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5>")]
     [(equal? (public-key-tweak-add pk t) (secret-key->public-key (secret-key-tweak-add one t)))
      "#t"]))))
