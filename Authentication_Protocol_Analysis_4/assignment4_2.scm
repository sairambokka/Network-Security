(defprotocol assignment4_2 basic
	(defrole alice
		(vars (a b name) (m text) (k skey))
		(trace 
		 (send (cat (enc m k) a (enc (hash (enc m k)) b (privk a)) (enc k (pubk b))))
		)
	)
	(defrole bob
		(vars (a b name) (m text) (k skey))
		(trace
		 (recv (cat (enc m k) a (enc (hash (enc m k)) b (privk a)) (enc k (pubk b))))
		)
	)
)

(defskeleton assignment4_2
	(vars (a b name) (m text) (k skey))
	(defstrandmax alice (a a) (b b) (m m) (k k))
	(non-orig (privk a) (privk b))
)

(defskeleton assignment4_2
	(vars (a b name) (m text) (k skey))
	(defstrandmax bob (a a) (b b) (m m) (k k))
	(non-orig (privk a) (privk b))
)
