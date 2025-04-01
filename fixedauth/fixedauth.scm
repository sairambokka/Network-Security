(defprotocol assignment4 basic
	(defrole alice
		(vars (a b name) (m text) (k skey))
		(trace 
		 (send (cat (enc m a (enc (hash m) (privk a)) k) (enc k (pubk b))))
		)
	)
	(defrole bob
		(vars (a b name) (m text) (k skey))
		(trace
		 (recv (cat (enc m a (enc (hash m) (privk a)) k) (enc k (pubk b))))
		)
	)
)

(defskeleton assignment4
	(vars (a b name) (m text))
	(defstrandmax alice (a a) (b b) (m m))
	(non-orig (privk a) (privk b))
)

(defskeleton assignment4
	(vars (a b name) (m text))
	(defstrandmax bob (a a) (b b) (m m))
	(non-orig (privk a) (privk b))
)
