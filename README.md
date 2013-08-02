## Eggdrop 1.8 SASL patch:

The `preinit-server` patch was merged into Eggdrop 1.8 recently, so you do not need to patch it manually anymore.

 0. For convenience, download this entire gist with `git clone https://gist.github.com/4455067.git`

 1. Get Eggdrop 1.8 [from CVS][eggcvs] or [from Git][egggit]. Compile and install.

 2. From your Eggdrop config, `source` the scripts and set the SASL information.

    ```tcl
    source "scripts/4455067/g_base64.tcl"
    source "scripts/4455067/g_cap.tcl"

    set sasl-user $username
    set sasl-pass "blahblah"

    # Let's turn off all "experimental" crap I added to g_cap
    set caps-wanted "sasl"
    ```

 3. Enjoy.

## Atheme auto-reop script:

 1. From your Eggdrop config, `source` the **g_atheme_need.tcl** script.

 2. Add a user named `services` to your bot, with ChanServ's hostmask, and give it the +fS flags.

        .+user services *!*@services.example.com
        .chattr services +fS

    Otherwise the bot can think it's being notice-flooded by ChanServ and ignore it.

[eggcvs]: http://www.eggheads.org/devel/
[egggit]: https://github.com/eggheads/eggdrop-1.8
