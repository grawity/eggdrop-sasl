# g_scram.tcl - SASL SCRAM-SHA-1/SHA-256 mechanism
# (c) 2019 Mantas Mikulėnas <grawity@gmail.com>
# Released under the MIT Expat License.
#
# Requires: g_pbkdf2.tcl, g_cap.tcl

package require Tcl 8.2
package require sha1
package require sha256

if {[namespace exists ::pbkdf2] == ""} {
	die "You must load g_pbkdf2.tcl first."
}

set sasl-scram-auto-upgrade 1

proc scram:escape {str} {
	return [string map {= =3D , =2C} $str]
}

proc scram:mknonce {length} {
	set fp [open /dev/urandom r]
	fconfigure $fp -translation binary
	set buf [read $fp $length]
	close $fp
	return [string range [b64:encode $buf] 0 $length]
}

proc scram:kvparse {string} {
	array set kvps {}
	foreach word [split $string ","] {
		if {[regexp {^([A-Za-z])=(.*)$} $word _ k v]} {
			set kvps($k) [string map {=2C , =3D =} $v]
		} else {
			return
		}
	}
	return [array get kvps]
}

proc scram:xorbuf {a b} {
	binary scan $a cu* abuf
	binary scan $b cu* bbuf
	set cbuf [lmap ai $abuf bi $bbuf {expr {$ai ^ $bi}}]
	return [binary format cu* $cbuf]
}

proc scram:upgrade-config {pass} {
	global config
	global sasl-scram-auto-upgrade
	putlog "SCRAM: You should now change sasl-pass to this token: \"$pass\""
	if {${sasl-scram-auto-upgrade} == 0} {return}
	catch {
		putlog "SCRAM: Automatically storing password hash in $config"
		set map {\" \\\" \{ \\\{ \} \\\} $ \\$ [ \\[ ] \\] \\ \\\\}
		set fh [open $config a]
		puts $fh ""
		puts $fh "# Automatically added by g_scram.tcl"
		puts $fh "set sasl-pass \"[string map $map $pass]\""
		close $fh
	}
}

proc scram:step {step data algo} {
	global sasl-user
	global sasl-pass
	global scram-state

	if {$algo == "sha1"} {
		set dfunc ::sha1::sha1
		set mfunc ::sha1::hmac
	} elseif {$algo == "sha256"} {
		set dfunc ::sha2::sha256
		set mfunc ::sha2::hmac
	} else {
		putlog "ERROR: unknown algorithm '$algo'"
		return "*"
	}

	if {$step == 1 && $data == "+"} {
		set cGs2Header "n,,"
		set cNonce [scram:mknonce 32]
		# optional: a=${sasl-authzid}
		set cInitMsg "n=[scram:escape ${sasl-user}],r=${cNonce}"
		array unset scram-state *
		set scram-state(cGs2Header) $cGs2Header
		set scram-state(cNonce) $cNonce
		set scram-state(cInitMsg) $cInitMsg
		return [b64:encode "${cGs2Header}${cInitMsg}"]
	} elseif {$step == 2 && $data != "+"} {
		set sFirstMsg [b64:decode $data]
		array set sKvps [scram:kvparse $sFirstMsg]
		if {[array get sKvps] == ""} {
			putlog "ERROR: could not parse SCRAM message '${data}'"
			return "*"
		}
		if {[info exists sKvps(m)]} {
			putlog "ERROR: unsupported extension attribute in SCRAM challenge"
			return "*"
		}
		if {![info exists sKvps(i)] || $sKvps(i) == ""} {
			putlog "ERROR: iteration count missing from SCRAM challenge"
			return "*"
		}
		if {![info exists sKvps(r)] || $sKvps(r) == ""} {
			putlog "ERROR: server nonce missing from SCRAM challenge"
			return "*"
		}
		if {![info exists sKvps(s)] || $sKvps(s) == ""} {
			putlog "ERROR: salt missing from SCRAM challenge"
			return "*"
		}
		set sNonce $sKvps(r)
		set cNonce ${scram-state(cNonce)}
		if {[string length $sNonce] <= [string length $cNonce]} {
			putlog "ERROR: server nonce truncated in SCRAM challenge"
			return "*"
		}
		if {[string range $sNonce 0 [string length $cNonce]-1] != $cNonce} {
			putlog "ERROR: server/client nonce prefix mismatch in SCRAM challenge"
			return "*"
		}
		# check whether we have the cached hash
		if {[string range ${sasl-pass} 0 5] == "scram:"} {
			set passTmp [string range ${sasl-pass} 6 end]
			array set pKvps [scram:kvparse $passTmp] 
			if {$pKvps(a) != $algo || $pKvps(s) != $sKvps(s) || $pKvps(i) != $sKvps(i)} {
				putlog "ERROR: sasl-pass is not for this server (algorithm, salt, and/or iteration count mismatch)"
				return "*"
			}
			if {[info exists pKvps(C)] && [info exists pKvps(S)]} {
				set clientKey [b64:decode $pKvps(C)]
				set serverKey [b64:decode $pKvps(S)]
			} elseif {[info exists pKvps(H)]} {
				set saltedPassword [b64:decode $pKvps(H)]
				set clientKey [$mfunc -bin -key $saltedPassword -- "Client Key"]
				set serverKey [$mfunc -bin -key $saltedPassword -- "Server Key"]
			} else {
				putlog "ERROR: sasl-pass is missing required attributes"
				return "*"
			}
		} else {
			set sSalt [b64:decode $sKvps(s)]
			set sIter $sKvps(i)
			if {$sSalt == ""} {
				putlog "ERROR: server provided invalid salt in SCRAM challenge"
				return "*"
			}
			if {![string is integer $sIter] || $sIter < 500 || $sIter > 65535} {
				putlog "ERROR: server provided invalid iteration count in SCRAM challenge"
				return "*"
			}
			putlog "SCRAM: Plaintext password found in 'sasl-pass'. Calculating PBKDF2 ($sIter iterations)..."
			putlog "This will take a minute or two. The server will probably kick you off."
			set saltedPassword [::pbkdf2::pbkdf2 $algo ${sasl-pass} $sSalt $sIter]
			set clientKey [$mfunc -bin -key $saltedPassword -- "Client Key"]
			set serverKey [$mfunc -bin -key $saltedPassword -- "Server Key"]
			# Cache the value for subsequent reconnections
			set sasl-pass "scram:a=$algo,s=${sKvps(s)},i=${sKvps(i)},H=[b64:encode $saltedPassword]"
			#set sasl-pass "scram:a=$algo,s=${sKvps(s)},i=${sKvps(i)},C=[b64:encode $clientKey],S=[b64:encode $serverKey]"
			scram:upgrade-config ${sasl-pass}
		}
		set cGs2Header ${scram-state(cGs2Header)}
		set cInitMsg ${scram-state(cInitMsg)}
		set cFinalMsgBare "c=[b64:encode $cGs2Header],r=${sNonce}"
		set authMsg "$cInitMsg,$sFirstMsg,$cFinalMsgBare"
		set storedKey [$dfunc -bin -- $clientKey]
		set clientSig [$mfunc -bin -key $storedKey -- $authMsg]
		set serverSig [$mfunc -bin -key $serverKey -- $authMsg]
		set clientProof [scram:xorbuf $clientKey $clientSig]
		set cFinalMsg "$cFinalMsgBare,p=[b64:encode $clientProof]"
		set scram-state(serverSig) $serverSig
		return [b64:encode $cFinalMsg]
	} elseif {$step == 3 && $data != "+"} {
		set sFinalMsg [b64:decode $data]
		array set sKvps [scram:kvparse $sFinalMsg]
		if {[array get sKvps] == ""} {
			putlog "ERROR: could not parse SCRAM message '${data}'"
			return "*"
		}
		if {[info exists sKvps(e)]} {
			putlog "ERROR: server returns authentication error '${sKvps(v)}'"
			return "*"
		}
		if {[info exists sKvps(m)]} {
			putlog "ERROR: unsupported extension attribute in SCRAM challenge"
			return "*"
		}
		if {![info exists sKvps(v)] || $sKvps(v) == ""} {
			putlog "ERROR: server verifier missing from challenge"
			return "*"
		}
		set sVerifier [b64:decode $sKvps(v)]
		set serverSig ${scram-state(serverSig)}
		if {$sVerifier != $serverSig} {
			putlog "ERROR: received server signature does not match computed"
			return "*"
		}
		array unset scram-state *
		putlog "SCRAM: Server was successfully authenticated."
		return "+"
	} else {
		return "*"
	}
}

proc sasl:step:SCRAM-SHA-1 {step data} {
	return [scram:step $step $data sha1]
}

proc sasl:step:SCRAM-SHA-256 {step data} {
	return [scram:step $step $data sha256]
}
