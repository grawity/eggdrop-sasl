# g_cap.tcl - Experimental IRCv3 capability support, including SASL
# (c) 2013 <grawity@gmail.com>, under WTFPL v2 <http://sam.zoy.org/wtfpl>
#
# Requires: g_base64.tcl

if {[info procs b64:encode] == ""} {
	die "You must load g_base64.tcl first."
}

## Configuration

set caps-wanted "account-notify away-notify extended-join multi-prefix sasl"
#set caps-wanted "sasl"

set sasl-user "$username"
set sasl-pass "hunter2"

## Internal state -- do not change

set caps-enabled {}
set caps-preinit 0
set sasl-state 0
set sasl-mech "*"

## Utility functions

proc rparse {text} {
	#putlog "rparse in:  $text"
	if {[string index $text 0] == ":"} {
		set pos [string first " " $text]
		set vec [list [string range $text 0 [expr $pos-1]]]
	}

	set pos [string first " :" $text]
	if {$pos < 0} {
		set vec [split $text " "]
	} else {
		set vec [split [string range $text 0 [expr $pos-1]] " "]
		lappend vec [string range $text [expr $pos+2] end]
	}
	#putlog "rparse out: $vec"
	return $vec
}

## Raw CAP commands -- required

proc cap:on-connect {ev} {
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

proc raw:cap {from keyword rest} {
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

## Raw IRCv3 extension commands

proc raw:cap-account {from keyword rest} {
	user:account-changed $from $rest
	return 1
}

proc raw:cap-extjoin {from keyword rest} {
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

proc raw:cap-away {from keyword rest} {
	set vec [rparse $rest]
	user:away-changed $from [lindex $vec 0]
	return 0
}

## Raw IRC-SASL commands

proc raw:authenticate {from keyword rest} {
	sasl:step $rest
	return 1
}

proc numeric:sasl-logged-in {from keyword rest} {
	set vec [rparse $rest]
	putlog "Authenticated to services as [lindex $vec 2]."
	return 1
}

proc numeric:sasl-success {from keyword rest} {
	putnow "CAP END"
	return 1
}

proc numeric:sasl-failed {from keyword rest} {
	putlog "Authentication failed"
	# TODO: make this disconnect
	putnow "CAP END"
	#putnow "QUIT"
	return 1
}

## SASL mechanism functions

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

## IRCv3 extension events
#
# Currently these only print log messages. Any ideas on making them useful?

proc user:account-changed {from account} {
	set nuh [split $from "!"]
	set nick [lindex $nuh 0]
	if {$account == "*"} {
		putlog "$nick logged out"
		set hand [finduser $from]
	} else {
		putlog "$nick logged in as $account"
		set hand [finduser $from]
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

# Basic CAP commands -- required
bind EVNT - preinit-server	cap:on-connect
bind EVNT - init-server		cap:on-connect
bind raw - "CAP"		raw:cap

# SASL commands
bind raw - "AUTHENTICATE"	raw:authenticate
bind raw - "900"		numeric:sasl-logged-in
bind raw - "903"		numeric:sasl-success
bind raw - "904"		numeric:sasl-failed

# IRCv3 extensions -- currently useless
bind raw - "AWAY"		raw:cap-away
bind raw - "JOIN"		raw:cap-extjoin
bind raw - "ACCOUNT"		raw:cap-account

# EOF
