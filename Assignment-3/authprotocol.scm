(defprotocol authprotocol basic
	(defrole alice
		(vars (a b name) (na na1 nb text))
		(trace 
		 (send (cat na a))
		 (recv (enc nb na a (privk b)))
		 (send (enc na1 nb b (privk a)))))
	(defrole bob
		(vars (a b name) (na na1 nb text))
		(trace
		 (recv (cat na a))
		 (send (enc nb na a (privk b)))
		 (recv (enc na1 nb b (privk a)))))
)

(defskeleton authprotocol
	(vars (a b name) (na na1 text))
	(defstrandmax alice (a a) (b b) (na na) (na1 na1))
	(non-orig (privk a) (privk b))
	(uniq-orig na na1)
)

(defskeleton authprotocol
	(vars (a b name) (nb text))
	(defstrandmax bob (a a) (b b) (nb nb))
	(non-orig (privk a) (privk b))
	(uniq-orig nb)
)
