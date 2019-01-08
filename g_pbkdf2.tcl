# g_pbkdf2.tcl - PBKDF2-SHA1/SHA256 routine
# (c) 2019 Mantas Mikulėnas <grawity@gmail.com>
# Released under the MIT Expat License.
#
# Based on source code at <https://wiki.tcl-lang.org/page/PBKDF2>
#
# Requires: tcllib
#
# Note: Will be very slow (~1500 iterations per second per block), unless
# tcltrf, cryptkit, or critcl are installed.

package require Tcl 8.2
package require sha1
package require sha256

namespace eval ::pbkdf2 {
	variable version 2.0.0
}

proc ::pbkdf2::pbkdf2 {algo password salt count {dklen 0}} {
	if {$algo == "sha1"} {
		set hashbytes 20
		set mfunc ::sha1::hmac
	} elseif {$algo == "sha256"} {
		set hashbytes 32
		set mfunc ::sha2::hmac
	} else {
		error "unknown hash algorithm '$algo'"
	}
	if {$dklen == 0} {
		set dklen $hashbytes
	}
	if {$dklen > (2**32-1)*$hashbytes} {
		error "derived key too long"
	}
	set dkn [expr {int(ceil(double($dklen)/$hashbytes))}]
	set dkl [list]
	for {set i 1} {$i <= $dkn} {incr i} {
		set xsalt [$mfunc -bin -key $password "$salt[binary format I $i]"]
		binary scan $xsalt Iu* xbuf
		for {set j 1} {$j < $count} {incr j} {
			set xsalt [$mfunc -bin -key $password $xsalt]
			binary scan $xsalt Iu* ybuf
			set xbuf [lmap x $xbuf y $ybuf {expr {$x ^ $y}}]
		}
		set dkl [concat $dkl $xbuf]
	}
	return [string range [binary format Iu* $dkl] 0 [incr dklen -1]]
}
