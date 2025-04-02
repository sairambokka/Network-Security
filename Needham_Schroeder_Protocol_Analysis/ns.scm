(herald "Needham-Schroeder Symmetric-Key Protocol")

(defprotocol ns basic
	(defrole alice
		(vars (a b s name) (na nb text) (m mesg) (sk skey))
		(trace (send (cat a b na))
			   (recv (enc na b sk m (ltk a s)))
			   (send m)
			   (recv (enc nb sk))
			   (send (enc (hash nb) sk))))

	(defrole authserv 
		(vars (a b s name) (na text) (sk skey))
		(trace (recv (cat a b na))
				   (send (enc na b sk (enc sk a (ltk b s)) (ltk a s)))
					 (send sk))
		(uniq-orig sk))

	(defrole bob
		(vars (a b s name) (nb text) (sk skey))
		(trace (recv (enc sk a (ltk b s)))
			   (send (enc nb sk))
			   (recv (enc (hash nb) sk)))))

(defskeleton ns
  (vars (a b s name) (m mesg) (na text))
  (defstrandmax alice (a a) (b b) (s s) (na na))
  (non-orig (ltk a s) (ltk b s))
  (uniq-orig na)
  (comment "Initiator point-of-view"))

(defskeleton ns
  (vars (a b s name) (nb text))
  (defstrandmax bob (a a) (b b) (s s) (nb nb))
  (non-orig (ltk a s) (ltk b s))
  (uniq-orig nb)
  (comment "Responder point-of-view"))