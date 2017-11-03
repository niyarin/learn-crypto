(define-library (niyarin-crypto des)


(import (scheme base)
        (srfi 60)
        (scheme write))

(export des-encrypt)

(begin
;
;        IP 
;

(define ip-table 
   #u8(58 50 42 34 26 18 10 2
     60 52 44 36 28 20 12 4 
     62 54 46 38 30 22 14 6 
     64 56 48 40 32 24 16 8
     57 49 41 33 25 17  9 1 
     59 51 43 35 27 19 11 3 
     61 53 45 37 29 21 13 5 
     63 55 47 39 31 23 15 7 ))


(define inv-ip-table
   #u8(40 8 48 16 56 24 64 32
       39 7 47 15 55 23 63 31
       38 6 46 14 54 22 62 30
       37 5 45 13 53 21 61 29
       36 4 44 12 52 20 60 28
       35 3 43 11 51 19 59 27
       34 2 42 10 50 18 58 26
       33 1 41  9 49 17 57 25))

(define (ip-aux block table)
   (let ((res (make-bytevector 64)))
      (do ([i 0 (+ i 1)])
          ((= i 64) res)
          (bytevector-u8-set! res i (bytevector-u8-ref block (- (bytevector-u8-ref table i) 1))))))

(define (ip block)
   (ip-aux block ip-table))

(define (inv-ip block)
   (ip-aux block inv-ip-table))


;
;       PC
;


(define pc1-table
 #u8(57 49 41 33 25 17 9 1 58 50 42 34 26 18 10 2 59 51 43 35 27 19 11 3 60 52 44 36
     63 55 47 39 31 23 15 7 62 54 46 38 30 22 14 6 61 53 45 37 29 21 13 5 28 20 12 4))

(define pc2-table
 #u8(14 17 11 24 1 5 3 28 15 6 21 10 23 19 12 4 26 8 16 7 27 20 13 2 41 52 31 37 47 55 30 40 51 45 33 48 44 49 39 56 34 53 46 42 50 36 29 32 ))


(define (pc-aux block table)
   (let* ([rlen (bytevector-length table)]
          [res (make-bytevector rlen)])
      (do ([i 0 (+ i 1)])
          ((= i rlen) res)
          (bytevector-u8-set! res i (bytevector-u8-ref block (- (bytevector-u8-ref table i) 1))))))


(define (pc1 block)
   (pc-aux block pc1-table))

(define (pc2 block)
   (pc-aux block pc2-table))


;
;      Expansion
;


(define e-table 
  #u8(32 1 2 3 4 5 4 5 6 7 8 9 8 9 10 11 12 13 12 13 14 15 16 17 16 17 18 19 20 21 20 21 22 23 24 25 24 25 26 27 28 29 28 29 30 31 32 1))


(define (expand block)
   (pc-aux block e-table))



(define (bytevector-circular-shift! block n)
   (let* ((block-size (bytevector-length block))
          (n (modulo (+ (- n) block-size)  block-size)))
      (let ((tmp-space (make-bytevector n)))
         (do ([i 0 (+ i 1)])
             ((= i n))
             (bytevector-u8-set! tmp-space i (bytevector-u8-ref block i)))
      
         (do ([i (- block-size 1) (- i 1)])
             ((< i n))
             (bytevector-u8-set! block (modulo (+ i n) block-size) (bytevector-u8-ref block i)))
         (do ([i 0 (+ i 1)]
              [j n (modulo (+ j 1) block-size)])
             ((= i n))
             (bytevector-u8-set! block j (bytevector-u8-ref tmp-space i))))))


(define (bytevector-circular-shift block n)
   (let* ((block-size (bytevector-length block))
          (res (make-bytevector block-size))
          (n (modulo (+ n block-size) block-size)))
      (do ([i 0 (+ i 1)])
          ((= i block-size) res)
          (bytevector-u8-set! res (modulo (+ i n) block-size) (bytevector-u8-ref block i)))))




;
;       Transpose
;

(define p-table
  #u8(16 7 20 21 29 12 28 17 1 15 23 26 5 18 31 10 2 8 24 14 32 27 3 9 19 13 30 6 22 11 4 25))




(define (transpose block)
   (pc-aux block p-table))



;
;        S-box
;

(define s-table
#(
 #u8(14 4 13 1 2 15 11 8 3 10 6 12 5 9 0 7 0 15 7 4 14 2 13 1 10 6 12 11 9 5 3 8 4 1 14 8 13 6 2 11 15 12 9 7 3 10 5 0 15 12 8 2 4 9 1 7 5 11 3 14 10 0 6 13)
 #u8(15 1 8 14 6 11 3 4 9 7 2 13 12 0 5 10 3 13 4 7 15 2 8 14 12 0 1 10 6 9 11 5 0 14 7 11 10 4 13 1 5 8 12 6 9 3 2 15 13 8 10 1 3 15 4 2 11 6 7 12 0 5 14 9)
 #u8(10 0 9 14 6 3 15 5 1 13 12 7 11 4 2 8 13 7 0 9 3 4 6 10 2 8 5 14 12 11 15 1 13 6 4 9 8 15 3 0 11 1 2 12 5 10 14 7 1 10 13 0 6 9 8 7 4 15 14 3 11 5 2 12)
 #u8(7 13 14 3 0 6 9 10 1 2 8 5 11 12 4 15 13 8 11 5 6 15 0 3 4 7 2 12 1 10 14 9 10 6 9 0 12 11 7 13 15 1 3 14 5 2 8 4 3 15 0 6 10 1 13 8 9 4 5 11 12 7 2 14)
 #u8(2 12 4 1 7 10 11 6 8 5 3 15 13 0 14 9 14 11 2 12 4 7 13 1 5 0 15 10 3 9 8 6 4 2 1 11 10 13 7 8 15 9 12 5 6 3 0 14 11 8 12 7 1 14 2 13 6 15 0 9 10 4 5 3)
 #u8(12 1 10 15 9 2 6 8 0 13 3 4 14 7 5 11 10 15 4 2 7 12 9 5 6 1 13 14 0 11 3 8 9 14 15 5 2 8 12 3 7 0 4 10 1 13 11 6 4 3 2 12 9 5 15 10 11 14 1 7 6 0 8 13)
 #u8(4 11 2 14 15 0 8 13 3 12 9 7 5 10 6 1 13 0 11 7 4 9 1 10 14 3 5 12 2 15 8 6 1 4 11 13 12 3 7 14 10 15 6 8 0 5 9 2 6 11 13 8 1 4 10 7 9 5 0 15 14 2 3 1)
 #u8(13 2 8 4 6 15 11 1 10 9 3 14 5 0 12 7 1 15 13 8 10 3 7 4 12 5 6 11 0 14 9 2 7 11 4 1 9 12 14 2 0 6 10 13 15 3 5 8 2 1 14 7 4 10 8 13 15 12 9 0 3 5 6 11)))




(define (s-box ci s-index)
   (let ([si (vector-ref s-table s-index)]
         [row-index 
            (+ (* (bytevector-u8-ref ci 0) 2) (bytevector-u8-ref ci 5) )]
         [column-index
            (+ (* (bytevector-u8-ref ci 1) 8)
               (* (bytevector-u8-ref ci 2) 4)
               (* (bytevector-u8-ref ci 3) 2)
               (* (bytevector-u8-ref ci 4) 1))])
      (let ([c (bytevector-u8-ref si (+ (* row-index 16) column-index))])
              (bytevector 
                    (ash (logand c 8) -3)
                    (ash (logand c 4) -2)
                    (ash (logand c 2) -1)
                    (logand c 1) ))))



(define (des p k)
   (let ([ki (make-vector 17)])

      (let* ([cd (pc1 k)]
             [c (bytevector-copy cd 0 28)]
             [d (bytevector-copy cd 28 56)])
        
         (do ([i 1 (+ i 1)])
             ((= i 17))
             (let ([v (case i ((1 2 9 16) 1)(else 2))])
                (bytevector-circular-shift! c v)
                (bytevector-circular-shift! d v)
                (vector-set! ki i (pc2 (bytevector-append c d))))))


      (let* ([lr (ip p)]
             [l (bytevector-copy lr 0 32)]
             [r (bytevector-copy lr 32 64)])
         (do ([des-cnt 1 (+ des-cnt 1)])
             ((= des-cnt 17) (inv-ip (bytevector-append r l)))
             (let ([r-xor-k (make-bytevector 48)]
                   [expanded-r (expand r)]
                   [current-k (vector-ref ki des-cnt)]
                   [fr (make-bytevector 32)])
                (do ([i 0 (+ i 1)])
                    ((= i 48))
                    (bytevector-u8-set! 
                       r-xor-k
                       i
                       (logxor
                          (bytevector-u8-ref expanded-r i)
                          (bytevector-u8-ref current-k i))))

               (do ([i 0 (+ i 1)])
                   ((= i 8))
                   (bytevector-copy! 
                      fr
                      (* i 4)
                      (s-box (bytevector-copy r-xor-k (* i 6) (* (+ i 1) 6) ) i )
                      0
                      4))
               (set! fr (transpose fr))

               (let ((tmp-l l))
                  (set! l r)
                  (set! r tmp-l))
               (do ([i 0 (+ i 1)])
                   ((= i 32))
                   (bytevector-u8-set! 
                      r
                      i
                      (logxor 
                         (bytevector-u8-ref r i)
                         (bytevector-u8-ref fr i))))
               ))))) 


(define (string->bytevector str)
   (let ((res (make-bytevector 64)))
      (do ([i 0 (+ i 1)])
          ((= i 8) res)
          (let ([ch (char->integer (string-ref str i))])
             (do ([j 0 (+ j 1)]
                  [bit 128 (quotient bit 2)]
                  [shift -7 (+ shift 1)])
                 ((= j 8))
                 (bytevector-u8-set! res (+ (* i 8) j) (ash (logand ch bit) shift)))))))




(define (des-encrypt plain key)
   (let* ([padded-plain 
           (string-append plain (make-string (modulo (- 8 (modulo (string-length plain) 8)) 8)))]
          [number-of-block (quotient (string-length padded-plain) 8)]
          [key (string->bytevector 
                  (string-append key (make-string (modulo (- 8 (modulo (string-length key) 8)) 8))))]
          [res (make-bytevector (* number-of-block 64))])
      (do ([i 0 (+ i 1)])
          ((= i number-of-block) res)
          (let* ([block (make-bytevector 64)]
                 [str (substring padded-plain (* i 8) (* (+ i 1) 8))]
                 [c (des (string->bytevector str) key)])
             (do ([j 0 (+ j 1)])
                 ((= j 64))
                 (bytevector-u8-set! res (+ (* i 64) j) (bytevector-u8-ref c j)))
             ))))

)
)


;
;  examples
;

;(import (scheme base) (scheme write) (niyarin-crypto des))
;(display 
;   (des-encrypt "My name is niyarin." "vwzabcde"))
;(newline)
