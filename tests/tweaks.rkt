#lang racket/base

(module+ test
  (require rackunit
           libsecp256k1
           "helpers/util.rkt")

  (define (key->integer key) (bytes->integer (secret-key->bytes key)))
  (define (integer->key v) (bytes->secret-key (integer->bytes32 v)))
  (define (pub key) (secret-key->public-key key))

  (define (random-tweak rng)
    (case (random 4 rng)
      [(0) (integer->bytes32 (random 1000 rng))]
      [else (random-secret-bytes rng)]))

  (test-seeded "secret-key-tweak-add is k + t mod n" #:seed (171 172 173 174 175 176) rng
    (for ([bs (in-list (secret-samples rng 300))])
      (define key (bytes->secret-key bs))
      (define t (random-tweak rng))
      (define sum (modulo (+ (bytes->integer bs) (bytes->integer t)) n))
      (unless (zero? sum)
        (check-equal? (key->integer (secret-key-tweak-add key t)) sum))))

  (test-seeded "tweaking the secret key and the public key agree" #:seed (181 182 183 184 185 186) rng
    (for ([bs (in-list (secret-samples rng 300))])
      (define key (bytes->secret-key bs))
      (define t (random-tweak rng))
      (check-equal? (pub (secret-key-tweak-add key t)) (public-key-tweak-add (pub key) t))))

  (test-seeded "public-key-tweak-add is P + tG" #:seed (191 192 193 194 195 196) rng
    (for ([bs (in-list (secret-samples rng 300))])
      (define p (pub (bytes->secret-key bs)))
      (define t (random-secret-bytes rng))
      (check-equal? (public-key-tweak-add p t)
                    (public-key-combine p (pub (bytes->secret-key t))))))

  (test-case "tweak 0 is the identity; t >= n and a zero sum raise"
    (define key (integer->key 12345))
    (define zero (make-bytes 32 0))
    (check-equal? (key->integer (secret-key-tweak-add key zero)) 12345)
    (check-equal? (public-key-tweak-add (pub key) zero) (pub key))
    (for ([t (list (integer->bytes32 n) (integer->bytes32 (+ n 1)) (make-bytes 32 255))])
      (check-exn exn:fail:libsecp256k1:key? (lambda () (secret-key-tweak-add key t)))
      (check-exn exn:fail:libsecp256k1:key? (lambda () (public-key-tweak-add (pub key) t))))
    (define cancel (integer->bytes32 (- n 12345)))
    (check-exn (regexp (regexp-quote
                        (string-append "secret-key-tweak-add: invalid tweak;\n"
                                       " the tweak is not less than the curve order, or the sum"
                                       " is zero")))
               (lambda () (secret-key-tweak-add key cancel)))
    (check-exn (regexp (regexp-quote
                        (string-append "public-key-tweak-add: invalid tweak;\n"
                                       " the tweak is not less than the curve order, or the sum"
                                       " is the point at infinity")))
               (lambda () (public-key-tweak-add (pub key) cancel))))

  (test-seeded "negation is n - k and -P" #:seed (201 202 203 204 205 206) rng
    (for ([bs (in-list (secret-samples rng 300))])
      (define key (bytes->secret-key bs))
      (define negated (secret-key-negate key))
      (check-equal? (key->integer negated) (- n (bytes->integer bs)))
      (check-equal? (key->integer (secret-key-negate negated)) (bytes->integer bs))
      (define p (public-key->bytes (pub key)))
      (define q (public-key->bytes (public-key-negate (pub key))))
      (check-equal? (pub negated) (public-key-negate (pub key)))
      (check-equal? (subbytes q 1) (subbytes p 1))
      (check-equal? (+ (bytes-ref p 0) (bytes-ref q 0)) 5)
      (check-equal? (public-key-negate (public-key-negate (pub key))) (pub key))))

  (test-seeded "combining is commutative and associative" #:seed (211 212 213 214 215 216) rng
    (for ([_ (in-range 200)])
      (define-values (a b c)
        (values (pub (bytes->secret-key (random-secret-bytes rng)))
                (pub (bytes->secret-key (random-secret-bytes rng)))
                (pub (bytes->secret-key (random-secret-bytes rng)))))
      (check-equal? (public-key-combine a b) (public-key-combine b a))
      (check-equal? (public-key-combine (public-key-combine a b) c)
                    (public-key-combine a (public-key-combine b c)))
      (check-equal? (public-key-combine a b c) (public-key-combine c (public-key-combine a b)))))

  (test-seeded "combining with itself doubles, and with its negation raises"
    #:seed (221 222 223 224 225 226) rng
    (for ([bs (in-list (secret-samples rng 100))])
      (define k (bytes->integer bs))
      (define p (pub (bytes->secret-key bs)))
      (check-equal? (public-key-combine p) p)
      (check-equal? (public-key-combine p p) (pub (integer->key (modulo (* 2 k) n))))
      (check-exn #rx"^public-key-combine: the sum is the point at infinity$"
                 (lambda () (public-key-combine p (public-key-negate p))))))

  (test-case "a sum is not cancelled by an intermediate infinity"
    (define p (pub (integer->key 7)))
    (define q (pub (integer->key 11)))
    (check-equal? (public-key-combine p (public-key-negate p) q) q)))
