## Eggdrop 1.8 SASL script:

 0. For convenience, download this entire gist with `git clone https://gist.github.com/4455067.git`

 1. Get Eggdrop 1.8 [from Git][egggit] or [from CVS][eggcvs]. Compile and install.
 
    The `preinit-server` patch was [merged into Eggdrop 1.8][commit] recently, so you do not need to patch it manually anymore.

 2. From your Eggdrop config, `source` the scripts and set the SASL information.

    ```tcl
    source "scripts/4455067/g_base64.tcl"
    source "scripts/4455067/g_cap.tcl"

    set sasl-user "NoobBot"
    set sasl-pass "blahblah"
    ```

(For those who still need it, the [patch for 1.6.x][patch] is still there.)

## Atheme auto-reop script:

 1. From your Eggdrop config, `source` the **g_atheme_need.tcl** script.

 2. Add a user named `services` to your bot, with ChanServ's hostmask, and give it the +fS flags.

        .+user services *!*@services.example.com
        .chattr services +fS

    Otherwise the bot can think it's being notice-flooded by ChanServ and ignore it.

[eggcvs]: http://www.eggheads.org/devel/
[egggit]: https://github.com/eggheads/eggdrop
[commit]: https://github.com/eggheads/eggdrop/commit/4847a9efbcaf260f1336ac735a785dd643714e62
[patch]: https://gist.github.com/grawity/4455067/eb63e5e1764df2a4d9979fbdb52554e698da3ce1#file-preinit-server-patch
