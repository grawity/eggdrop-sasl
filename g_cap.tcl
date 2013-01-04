## Configuration

set caps-wanted "account-notify away-notify extended-join multi-prefix sasl"

set sasl-user "Neph"
set sasl-pass "lemonysnicket"

## Internal state

set caps-enabled {}
set caps-preinit 0
set sasl-state 0
set sasl-mech "*"

## Utility functions

proc rparse {text} {
	#putlog "rparse in:  $text"
	if {[string index $text 0] == ":"} {
		set vec [list [string range $text 1 end]]
	} else {
		set pos [string first " :" $text]
		if {$pos < 0} {
			set vec [split $text " "]
		} else {
			set vec [split [string range $text 0 [expr $pos-1]] " "]
			lappend vec [string range $text [expr $pos+2] end]
		}
	}
	#putlog "rparse out: $vec"
	return $vec
}

if {![catch {package require Tcl 8.6}]} {
	proc b64:encode {bin} {
		binary encode base64 $bin
	}
	proc b64:decode {str} {
		binary decode base64 $str
	}
} elseif {![catch {package require base64}]} {
	proc b64:encode {bin} {
		::base64::encode -wrapchar "" $bin
	}
	proc b64:decode {bin} {
		::base64::decode $bin
	}
} else {
	die "No Base64 implementation found; need either Tcl 8.6 or tcllib/base64"
}

## Raw events

proc cap:connect {ev} {
	global caps-preinit
	switch $ev {
		"preinit-server" {
			set caps-preinit 1
			putnow "CAP LS"
		}
		"init-server" {
			set caps-preinit 0
		}
	}
	return 0
}

proc cap:cap {from keyword rest} {
	global caps-preinit
	global caps-wanted
	set vec [rparse [string trim $rest]]
	set cmd [lindex $vec 1]
	set caps [lindex $vec 2]
	if {${caps-preinit} == 0} {
		return 1
	}
	switch $cmd {
		LS {
			set wanted {}
			foreach cap $caps {
				if {[lsearch -exact ${caps-wanted} $cap] != -1} {
					lappend wanted $cap
				}
			}
			if {[llength $wanted]} {
				putnow "CAP REQ :[join $wanted " "]"
			}
		}
		ACK {
			if {[lsearch -exact $caps "sasl"] != -1} {
				sasl:start PLAIN
			} else {
				putnow "CAP END"
			}
		}
		NAK {
			putnow "CAP END"
		}
	}
	return 1
}

proc cap:account {from keyword rest} {
	user:account-changed $from $rest
	return 1
}

proc cap:extjoin {from keyword rest} {
	set nuh [split $from "!"]
	set vec [rparse $rest]
	if {[llength $vec] > 1} {
		set account [lindex $vec 1]
		set gecos [lindex $vec 2]
		user:account-changed $from $account
		user:gecos-changed $from $gecos
	}
	return 0
}

proc cap:away {from keyword rest} {
	set vec [rparse $rest]
	user:away-changed $from [lindex $vec 0]
	return 0
}

proc cap:authenticate {from keyword rest} {
	sasl:step $rest
	return 1
}

proc sasl:logged-in-as {from keyword rest} {
	set vec [rparse $rest]
	putlog "Authenticated to services as [lindex $vec 2]."
	return 1
}

proc sasl:success {from keyword rest} {
	putnow "CAP END"
	return 1
}

## SASL functions

proc sasl:start {mech} {
	global sasl-state
	global sasl-mech
	set sasl-state 1
	set sasl-mech $mech
	putlog "Starting SASL $mech authentication."
	sasl:step ""
}

proc sasl:step {data} {
	global sasl-state
	global sasl-mech
	if {${sasl-state} == 1} {
		putnow "AUTHENTICATE ${sasl-mech}"
	} else {
		sasl:step:${sasl-mech} $data
	}
	set sasl-state [expr ${sasl-state} + 1]
}

proc sasl:step:PLAIN {data} {
	global sasl-user
	global sasl-pass
	if {$data == "+"} {
		set out [join [list ${sasl-user} ${sasl-user} ${sasl-pass}] "\0"]
		putnow "AUTHENTICATE [b64:encode $out]"
	}
}

## User events

proc user:account-changed {from account} {
	set nuh [split $from "!"]
	set nick [lindex $nuh 0]
	if {$account == "*"} {
		putlog "$nick logged out"
		set hand [finduser $from]
		setuser $hand XTRA services-account
	} else {
		putlog "$nick logged in as $account"
		set hand [finduser $from]
		setuser $hand XTRA services-account $account
	}
}

proc user:gecos-changed {from gecos} {
	set nuh [split $from "!"]
	set nick [lindex $nuh 0]
	putlog "$nick is actually \"$gecos\""
}

proc user:away-changed {from reason} {
	set nuh [split $from "!"]
	set nick [lindex $nuh 0]
	if {$reason == ""} {
		putlog "$nick is back"
	} else {
		putlog "$nick is away"
	}
}

## Event bindings

bind raw - "ACCOUNT"		cap:account
bind raw - "AUTHENTICATE"	cap:authenticate
bind raw - "AWAY"		cap:away
bind raw - "CAP"		cap:cap
bind raw - "JOIN"		cap:extjoin
bind raw - "900"		sasl:logged-in-as
bind raw - "903"		sasl:success

bind EVNT - preinit-server	cap:connect
bind EVNT - init-server		cap:connect

# EOF
