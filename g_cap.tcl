# g_cap.tcl - IRCv3 capability negotiation and SASL support
# (c) 2013 <grawity@gmail.com>, under WTFPL v2 <http://sam.zoy.org/wtfpl>
#
# Requires: g_base64.tcl

## Configuration -- set these in your eggdrop.conf

set sasl-user "$username"
set sasl-pass "hunter2"

## Internal state -- do not edit anything below

if {[info procs b64:encode] == ""} {
	die "You must load g_base64.tcl first."
}

set caps-enabled {}
set caps-wanted {multi-prefix sasl}
set caps-preinit 0
set sasl-state 0
set sasl-mech "*"

## Utility functions

proc rparse {text} {
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
	return $vec
}

## Raw CAP commands

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

## Event bindings

bind EVNT - preinit-server	cap:on-connect
bind EVNT - init-server		cap:on-connect
bind raw - "CAP"		raw:cap

bind raw - "AUTHENTICATE"	raw:authenticate
bind raw - "900"		numeric:sasl-logged-in
bind raw - "903"		numeric:sasl-success
bind raw - "904"		numeric:sasl-failed

# EOF
