# g_base64.tcl - Base64 encoding/decoding routines
# (c) 2013 Mantas Mikulėnas <grawity@gmail.com>
# Released under the MIT Expat License.

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
