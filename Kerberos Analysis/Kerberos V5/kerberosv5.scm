(herald "Kerberos Version 5 - with pre-authentication"
	(bound 20)
	(limit 16000)
	)

(defmacro (ticket c s k adc ts l tktkey)
  (enc k c adc s ts l tktkey))

(defmacro (authenticator k c ts)
  (enc c ts k))

(defprotocol kerberos basic

  (defrole client
    (vars (c name) (as authserver) (tgs tktserver) (v server)
	  (kctgs kcv keytgs password skey) (ticket_tgs ticket_v mesg)
	  (ts1 ts2 ts3 ts4 ts5 l2 l4 time) (n1 n2 text) (adc data)) 
    (trace
     (send (cat c tgs ts1 n1 (enc ts1 (hash password c))))
     (recv (cat c ticket_tgs (enc kctgs tgs ts2 l2 n1 (hash password c))))
     (send (cat v ts3 n2 ticket_tgs (authenticator kctgs c ts3)))
     (recv (cat c ticket_v (enc kcv v ts4 l4 n2 kctgs)))
     (send (cat ticket_v (authenticator kcv c ts5)))
     (recv (enc ts5 kcv))
     )
    )

  (defrole authserver
    (vars (c name) (as authserver) (tgs tktserver) (n1 text)
	  (password kctgs keytgs skey) (ts1 ts2 l2 time) (adc data))
    (trace
     (recv (cat c tgs ts1 n1 (enc ts1 (hash password c))))
     (send (cat c (ticket c tgs kctgs adc ts2 l2 keytgs) (enc kctgs tgs ts2 l2 
		n1 (hash password c))))
     )
    (uniq-gen kctgs)
    (non-orig keytgs)
    )

  (defrole tgserver
    (vars (c name) (as authserver) (tgs tktserver) (v server) (n2 text)
	  (kctgs kcv keytgs keyv skey) (ts2 ts3 ts4 l2 l4 time) (adc data))
    (trace
     (recv (cat v ts3 n2 (ticket c tgs kctgs adc ts2 l2 keytgs)
		(authenticator kctgs c ts3)))
     (send (cat c (ticket c v kcv adc ts4 l4 keyv) (enc kcv v ts4 l4 n2 kctgs)))
     )
    (uniq-gen kcv)
    (non-orig keyv)
    )

  (defrole server
    (vars (c name) (tgs tktserver) (v server) (kcv keyv skey) (ts4 ts5 l4 time)
	  (adc data))
    (trace
     (recv (cat (ticket c v kcv adc ts4 l4 keyv) (authenticator kcv c ts5)))
     (send (enc ts5 kcv))
     )
    )

  (defgoal hash-of-password-unavailable
    (forall
     ((password skey) (c name) (z z-0 strd))
     (implies
      (and (p "client" z 2) (p "" z-0 2)
           (p "client" "password" z password)
           (p "client" "c" z c) (p "" "x" z-0 (hash password c))
           (non password))
      (false))))


  (lang
   (authserver atom)
   (tktserver atom)
   (server atom)
   (time atom))
  )

(defskeleton kerberos
  (vars (password skey) (n1 text))
  (defstrand client 2 (password password) (n1 n1))
  (non-orig password)
  (uniq-orig n1)
  )

(defskeleton kerberos
  (vars (password keytgs skey) (n1 n2 text))
  (defstrand client 4 (password password) (n1 n1) (n2 n2))
  (non-orig password)
  (uniq-orig n1 n2)
  )

(defskeleton kerberos
  (vars (password keytgs keyv skey) (n1 n2 text))
  (defstrand client 6 (password password) (n1 n1) (n2 n2))
  (non-orig password)
  (uniq-orig n1 n2)
  )

(defskeleton kerberos
  (vars (password keytgs skey))
  (defstrand authserver 2 (password password) (keytgs keytgs))
  (non-orig password keytgs)
  )

(defskeleton kerberos
  (vars (keytgs keyv skey))
  (defstrand tgserver 2 (keytgs keytgs) (keyv keyv))
  (non-orig keytgs keyv)
  )
  
(defskeleton kerberos
  (vars (keyv skey))
  (defstrand server 1 (keyv keyv))
  (non-orig keyv)
  )

(defprotocol kerberosS basic

  (defrole client
    (vars (c name) (as authserver) (tgs tktserver) (v server)
	  (kctgs kcv keytgs password skey) (ticket_tgs ticket_v mesg)
	  (ts1 ts2 ts3 ts4 ts5 l2 l4 time) (n1 n2 text) (adc data)) 
    (trace
     (send (cat c tgs ts1 n1 (enc ts1 (hash password c))))
     (recv (cat c ticket_tgs (enc kctgs tgs ts2 l2 n1 (hash password c))))
     (send (cat v ts3 n2 ticket_tgs (authenticator kctgs c ts3)))
     (recv (cat c ticket_v (enc kcv v ts4 l4 n2 kctgs)))
     (send (cat ticket_v (authenticator kcv c ts5)))
     (recv (enc ts5 kcv))
     )
    )

  (defrole authserver
    (vars (c name) (as authserver) (tgs tktserver) (n1 text)
	  (password kctgs keytgs skey) (ts1 ts2 l2 time) (adc data))
    (trace
     (recv (cat c tgs ts1 n1 (enc ts1 (hash password c))))
     (send (cat c (ticket c tgs kctgs adc ts2 l2 keytgs) (enc kctgs tgs ts2 l2 
		n1 (hash password c))))
     )
    (uniq-gen kctgs)
    (non-orig password)
    )

  (defrole tgserver
    (vars (c name) (as authserver) (tgs tktserver) (v server) (n2 text)
	  (kctgs kcv keytgs keyv skey) (ts2 ts3 ts4 l2 l4 time) (adc data))
    (trace
     (recv (cat v ts3 n2 (ticket c tgs kctgs adc ts2 l2 keytgs)
		(authenticator kctgs c ts3)))
     (send (cat c (ticket c v kcv adc ts4 l4 keyv) (enc kcv v ts4 l4 n2 kctgs)))
     )
    (uniq-gen kcv)
    (non-orig keytgs)
    )

  (defrole server
    (vars (c name) (tgs tktserver) (v server) (kcv keyv skey) (ts4 ts5 l4 time)
	  (adc data))
    (trace
     (recv (cat (ticket c v kcv adc ts4 l4 keyv) (authenticator kcv c ts5)))
     (send (enc ts5 kcv))
     )
    )

  (lang
   (authserver atom)
   (tktserver atom)
   (server atom)
   (time atom))
  )

(defskeleton kerberosS
  (vars (password keytgs skey))
  (defstrand authserver 2 (password password) (keytgs keytgs))
  (non-orig password keytgs)
  )

(defskeleton kerberosS
  (vars (keytgs keyv skey))
  (defstrand tgserver 2 (keytgs keytgs) (keyv keyv))
  (non-orig keytgs keyv)
  )
  
 (defskeleton kerberosS
  (vars (keyv skey))
  (defstrand server 1 (keyv keyv))
  (non-orig keyv)
  )

