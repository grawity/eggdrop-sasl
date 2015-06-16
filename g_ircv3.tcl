# g_ircv3.tcl - Experimental IRCv3 extension support
# (c) 2013 Mantas Mikulėnas <grawity@gmail.com>
# Released under the MIT Expat License.
#
# Requires: g_cap.tcl

## Configurable procs -- adjust to your needs

proc user:account-changed {from account} {
	set nuh [split $from "!"]
	set nick [lindex $nuh 0]
	if {$account == "*"} {
		putlog "$nick logged out"
	} else {
		putlog "$nick logged in as $account"
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

## Setup -- do not edit anything below

if {[info procs raw:CAP] == ""} {
	die "You must load g_cap.tcl first."
}

lappend caps-wanted {account-notify away-notify extended-join}

proc raw:ACCOUNT {from keyword rest} {
	user:account-changed $from $rest
	return 1
}

proc raw:JOIN-extended {from keyword rest} {
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

proc raw:AWAY {from keyword rest} {
	set vec [rparse $rest]
	user:away-changed $from [lindex $vec 0]
	return 0
}

bind raw - "AWAY"		raw:AWAY
bind raw - "JOIN"		raw:JOIN-extended
bind raw - "ACCOUNT"		raw:ACCOUNT
