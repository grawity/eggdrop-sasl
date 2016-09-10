# g_cap.tcl - IRCv3 capability negotiation and SASL support
# (c) 2013-2015 Mantas Mikulėnas <grawity@gmail.com>
# Released under the MIT Expat License.
#
# Requires: g_base64.tcl

## Configuration -- set these in your eggdrop.conf

# available mechs: EXTERNAL, PLAIN
set sasl-use-mechs {PLAIN}

# services username
set sasl-user "$username"

# password for PLAIN
set sasl-pass "hunter2"

# disconnect on failure?
set sasl-disconnect-on-fail 1

# extra capabilities to ask for
set caps-wanted {multi-prefix}

## Internal state -- do not edit anything below

if {[info procs b64:encode] == ""} {
	die "You must load g_base64.tcl first."
}

set caps-enabled {}
set caps-preinit 0
set sasl-mechs {}
set sasl-midx 0
set sasl-mech "*"
set sasl-step 0

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

proc raw:CAP {from keyword rest} {
	global caps-preinit
	global caps-wanted
	global sasl-user

	if {${caps-preinit} == 0} {
		return 1
	}

	set vec [rparse [string trim $rest]]
	set cmd [lindex $vec 1]
	set caps [lindex $vec 2]

	switch $cmd {
		LS {
			putlog "Server offers caps: $caps"
			set wanted {}
			foreach cap $caps {
				if {[lsearch -exact ${caps-wanted} $cap] != -1} {
					lappend wanted $cap
				} elseif {$cap == "sasl" && ${sasl-user} != ""} {
					lappend wanted $cap
				}
			}
			if {[llength $wanted]} {
				set wanted [join $wanted " "]
				putlog "Requesting caps: $wanted"
				putnow "CAP REQ :$wanted"
			} else {
				putnow "CAP END"
			}
		}
		ACK {
			putlog "Server enabled caps: $caps"
			if {[lsearch -exact $caps "sasl"] != -1} {
				sasl:start [sasl:get-first-mech]
			} else {
				putnow "CAP END"
			}
		}
		NAK {
			putlog "Server rejected caps: $caps"
			putnow "CAP END"
		}
	}
	return 1
}

## Raw IRC-SASL commands

proc raw:AUTHENTICATE {from keyword rest} {
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
	global sasl-disconnect-on-fail

	set mech [sasl:get-next-mech]
	if {$mech != "*"} {
		putlog "Authentication failed, trying next mechanism"
		sasl:start $mech
	} elseif {${sasl-disconnect-on-fail} == 1} {
		putlog "Authentication failed, disconnecting"
		putnow "QUIT"
		putnow "CAP END"
	} else {
		putlog "Authentication failed, continuing anyway"
		putnow "CAP END"
	}
	return 1
}

proc numeric:sasl-mechlist {from keyword rest} {
	global sasl-mechs

	set vec [rparse $rest]
	set sasl-mechs [lindex $vec 2]
	return 1
}

## SASL mechanism functions

proc sasl:get-first-mech {} {
	global sasl-use-mechs
	global sasl-mechs
	global sasl-midx

	set sasl-mechs ${sasl-use-mechs}
	set sasl-midx 0
	return [lindex ${sasl-use-mechs} 0]
}

proc sasl:get-next-mech {} {
	global sasl-use-mechs
	global sasl-mechs
	global sasl-midx

	while {[incr sasl-midx] < [llength ${sasl-use-mechs}]} {
		set mech [lindex ${sasl-use-mechs} ${sasl-midx}]
		if {[lsearch -exact ${sasl-mechs} $mech] != -1} {
			return $mech
		}
	}
	return "*"
}

proc sasl:start {mech} {
	global sasl-mech
	global sasl-step

	if {[info procs sasl:step:$mech] == ""} {
		putlog "ERROR: Mechanism '$mech' is not supported by this script!"
		putnow "AUTHENTICATE *"
		return
	}

	set sasl-mech $mech
	set sasl-step 0
	putlog "Starting SASL $mech authentication"
	sasl:step ""
}

proc sasl:step {data} {
	global sasl-mech
	global sasl-step

	if {${sasl-step} == 0} {
		putnow "AUTHENTICATE ${sasl-mech}"
	} else {
		set out [sasl:step:${sasl-mech} ${sasl-step} $data]
		set len 400
		set max [string length $out]
		set ofs 0
		while {$ofs < $max} {
			set buf [string range $out $ofs [expr {$ofs + $len - 1}]]
			incr ofs $len
			putnow "AUTHENTICATE $buf"
		}
		if {$max == 0 || [string length $buf] == $len} {
			putnow "AUTHENTICATE +"
		}
	}
	set sasl-step [expr ${sasl-step} + 1]
}

proc sasl:step:PLAIN {step data} {
	global sasl-user
	global sasl-pass

	if {$step == 1 && $data == "+"} {
		set out [join [list ${sasl-user} ${sasl-user} ${sasl-pass}] "\0"]
		return [b64:encode $out]
	} else {
		return "*"
	}
}

proc sasl:step:EXTERNAL {step data} {
	global sasl-user

	if {$step == 1 && $data == "+"} {
		return [b64:encode ${sasl-user}]
	} else {
		return "*"
	}
}

## Event bindings

bind EVNT - preinit-server	cap:on-connect
bind EVNT - init-server		cap:on-connect
bind raw - "CAP"		raw:CAP

bind raw - "AUTHENTICATE"	raw:AUTHENTICATE
bind raw - "900"		numeric:sasl-logged-in
bind raw - "903"		numeric:sasl-success
bind raw - "904"		numeric:sasl-failed
bind raw - "908"		numeric:sasl-mechlist

# EOF
