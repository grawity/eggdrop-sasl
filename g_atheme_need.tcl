# g_atheme_need.tcl - handles "need op/unban/invite/key" events with Atheme
# (c) 2011 Mantas Mikulėnas <grawity@gmail.com>
# Released under the MIT Expat License.

## Configuration
#
# 0) Load this script
# 1) Add a "services" user with ChanServ's hostmask
# 2) .chattr services +fS

proc need:op {channel type} {
	putlog "($channel) requesting reop"
	putquick "PRIVMSG ChanServ :op $channel"
}

proc need:unban {channel type} {
	putlog "($channel) requesting unban"
	putquick "PRIVMSG ChanServ :unban $channel"
}

proc need:invite {channel type} {
	putlog "($channel) requesting invite"
	putquick "PRIVMSG ChanServ :invite $channel"
}

proc need:key {channel type} {
	putlog "($channel) requesting key"
	putquick "PRIVMSG ChanServ :getkey $channel"
}

proc chanserv:recvkey {nick addr hand text dest} {
	set msg [split [stripcodes bcru $text] " "]
	set channel [lindex $msg 1]
	set key [lindex $msg 4]
	putlog "($channel) received key, joining channel"
	putquick "JOIN $channel $key"
	return 1
}

bind need - "% op"     need:op
bind need - "% unban"  need:unban
bind need - "% invite" need:invite
bind need - "% key"    need:key

bind notc S "Channel % key is: *" chanserv:recvkey
