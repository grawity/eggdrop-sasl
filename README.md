## Eggdrop 1.8 SASL script:

 0. For convenience, download this entire repository with `git clone https://github.com/grawity/eggdrop-sasl`

 1. Get Eggdrop 1.8 [from Git][egggit] or [from CVS][eggcvs]. Compile and install.
 
    The `preinit-server` patch was [merged into Eggdrop 1.8][commit] recently, so you do not need to patch it manually anymore.

 2. From your Eggdrop config, `source` the scripts and set the SASL information.

    ```tcl
    source "scripts/eggdrop-sasl/g_base64.tcl"
    source "scripts/eggdrop-sasl/g_cap.tcl"

    set sasl-user "NoobBot"
    set sasl-pass "blahblah"
    ```

(For those who still need it, the [patch for 1.6.x][patch] is still there.)

### SCRAM-SHA support

 3. To enable support for SCRAM-SHA-1 or SCRAM-SHA-256, first ensure _tcllib_ is installed, then load two additional scripts:

    ```tcl
    source "scripts/eggdrop-sasl/g_pbkdf2.tcl"
    source "scripts/eggdrop-sasl/g_scram.tcl"

    set sasl-use-mechs {SCRAM-SHA-256}
    ```

 4. Connect to the server. Note that PBKDF2-SHA is *very slow* in Tcl, and the first connection attempt may time out. Wait for Eggdrop to retry; the second attempt should work fine.

 5. To improve security, you can remove the plaintext password from your _eggdrop.conf_ and replace it with a hash. The script will automatically show the recommended hash to put in the `sasl-pass` field.

## Atheme auto-reop script:

 1. From your Eggdrop config, `source` the **g_atheme_need.tcl** script.

 2. Add a user named `services` to your bot, with ChanServ's hostmask, and give it the +fS flags.

        .+user services *!*@services.example.com
        .chattr services +fS

    Otherwise the bot can think it's being notice-flooded by ChanServ and ignore it.

[eggcvs]: http://www.eggheads.org/devel/
[egggit]: https://github.com/eggheads/eggdrop
[commit]: https://github.com/eggheads/eggdrop/commit/4847a9efbcaf260f1336ac735a785dd643714e62
[patch]: https://github.com/grawity/eggdrop-sasl/blob/eb63e5e1764df2a4d9979fbdb52554e698da3ce1/preinit-server.patch
