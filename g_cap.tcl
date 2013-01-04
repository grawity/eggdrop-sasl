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
	proc b64:encode {input} {
		binary encode base64 $input
	}
	proc b64:decode {input} {
		binary decode base64 $input
	}
} elseif {![catch {package require base64}]} {
	proc b64:encode {input} {
		::base64::encode -wrapchar "" $input
	}
	proc b64:decode {input} {
		::base64::decode $input
	}
} else {
	set b64map {A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
		    a b c d e f g h i j k l m n o p q r s t u v w x y z
		    0 1 2 3 4 5 6 7 8 9 + / =}

	proc b64:encode {input} {
		global b64map
		set str {}
		set pad 0
		binary scan $input c* X
		foreach {x y z} $X {
			if {$y == {}} {set y 0; incr pad}
			if {$z == {}} {set z 0; incr pad}
			set n [expr {($x << 16) | ($y << 8) | $z}]
			set a [expr {($n >> 18) & 63}]
			set b [expr {($n >> 12) & 63}]
			set c [expr {($n >>  6) & 63}]
			set d [expr {$n & 63}]
			append str \
				[lindex $b64map $a] \
				[lindex $b64map $b] \
				[lindex $b64map [expr {$pad >= 2 ? 64 : $c}]] \
				[lindex $b64map [expr {$pad >= 1 ? 64 : $d}]]
		}
		return $str
	}

	proc b64:decode {input} {
		set str {}
		set pos 0
		set pad 0
		set n 0
		binary scan $input c* X
		foreach x $X {
			if     {$x >= 65 && $x <= 90}  { set x [expr {$x - 65}] }\
			elseif {$x >= 97 && $x <= 122} { set x [expr {$x - 71}] }\
			elseif {$x >= 48 && $x <= 57}  { set x [expr {$x + 4}]  }\
			elseif {$x == 61}              { set x 0; incr pad      }\
			else                           { continue }
			set o [expr {18 - 6 * ($pos % 4)}]
			set n [expr {$n | ($x << $o)}]
			if {$o == 0} {
				set a [expr {($n >> 16) & 255}]
				set b [expr {($n >> 8) & 255}]
				set c [expr {$n & 255}]
				set n 0
				if {$pad == 2} {
					append str [binary format c $a]
					break
				} elseif {$pad == 1} {
					append str [binary format cc $a $b]
					break
				} else {
					append str [binary format ccc $a $b $c]
				}
			}
			incr pos
		}
		return $str
	}
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
