(herald "Kerberos Version 4 "
	(bound 20)
	(limit 16000)
	)

(defmacro (ticket c s k adc ts l tktkey)
  (enc k c adc s ts l tktkey))

(defmacro (authenticator k c adc ts)
  (enc c adc ts k))

(defprotocol kerberos basic

  (defrole client
    (vars (c name) (as authserver) (tgs tktserver) (v server)
	  (kctgs kcv keytgs password skey) (ticket_tgs ticket_v mesg)
	  (ts1 ts2 ts3 ts4 ts5 l2 l4 time) (adc data)) 
    (trace
     (send (cat c tgs ts1))
     (recv (enc kctgs tgs ts2 l2 ticket_tgs (hash password c)))
     (send (cat v ticket_tgs (authenticator kctgs c adc ts3)))
     (recv (enc kcv v ts4 l4 ticket_v kctgs))
     (send (cat ticket_v (authenticator kcv c adc ts5)))
     (recv (enc ts5 "+1" kcv))
     )
    )

  (defrole authserver
    (vars (c name) (as authserver) (tgs tktserver)
	  (password kctgs keytgs skey) (ts1 ts2 l2 time) (adc data))
    (trace
     (recv (cat c tgs ts1))
     (send (enc kctgs tgs ts2 l2 (ticket c tgs kctgs adc ts2 l2 keytgs)
		(hash password c)))
     )
    (uniq-gen kctgs)
    (non-orig keytgs)
    )

  (defrole tgserver
    (vars (c name) (as authserver) (tgs tktserver) (v server)
	  (kctgs kcv keytgs keyv skey) (ts2 ts3 ts4 l2 l4 time) (adc data))
    (trace
     (recv (cat v (ticket c tgs kctgs adc ts2 l2 keytgs)
		(authenticator kctgs c adc ts3)))
     (send (enc kcv v ts4 l4 (ticket c v kcv adc ts4 l4 keyv) kctgs))
     )
    (uniq-gen kcv)
    (non-orig keyv)
    )

  (defrole server
    (vars (c name) (tgs tktserver) (v server) (kcv keyv skey) (ts4 ts5 l4 time)
	  (adc data))
    (trace
     (recv (cat (ticket c v kcv adc ts4 l4 keyv) (authenticator kcv c adc ts5)))
     (send (enc ts5 "+1" kcv))
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
  (vars (password skey))
  (defstrand client 2 (password password))
  (non-orig password)
  )

(defskeleton kerberos
  (vars (password skey))
  (defstrand client 4 (password password))
  (non-orig password)
  )

(defskeleton kerberos
  (vars (password skey))
  (defstrand client 6 (password password))
  (non-orig password)
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
	  (ts1 ts2 ts3 ts4 ts5 l2 l4 time) (adc data)) 
    (trace
     (send (cat c tgs ts1))
     (recv (enc kctgs tgs ts2 l2 ticket_tgs (hash password c)))
     (send (cat v ticket_tgs (authenticator kctgs c adc ts3)))
     (recv (enc kcv v ts4 l4 ticket_v kctgs))
     (send (cat ticket_v (authenticator kcv c adc ts5)))
     (recv (enc ts5 "+1" kcv))
     )
    )

  (defrole authserver
    (vars (c name) (as authserver) (tgs tktserver)
	  (password kctgs keytgs skey) (ts1 ts2 l2 time) (adc data))
    (trace
     (recv (cat c tgs ts1))
     (send (enc kctgs tgs ts2 l2 (ticket c tgs kctgs adc ts2 l2 keytgs)
		(hash password c)))
     )
    (uniq-gen kctgs)
    (non-orig password)
    )

  (defrole tgserver
    (vars (c name) (as authserver) (tgs tktserver) (v server)
	  (kctgs kcv keytgs keyv skey) (ts2 ts3 ts4 l2 l4 time) (adc data))
    (trace
     (recv (cat v (ticket c tgs kctgs adc ts2 l2 keytgs)
		(authenticator kctgs c adc ts3)))
     (send (enc kcv v ts4 l4 (ticket c v kcv adc ts4 l4 keyv) kctgs))
     )
    (uniq-gen kcv)
    (non-orig keytgs)
    )

  (defrole server
    (vars (c name) (tgs tktserver) (v server) (kcv keyv skey) (ts4 ts5 l4 time)
	  (adc data))
    (trace
     (recv (cat (ticket c v kcv adc ts4 l4 keyv) (authenticator kcv c adc ts5)))
     (send (enc ts5 "+1" kcv))
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

