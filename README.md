## Eggdrop 1.8 SASL patch:

 0. For convenience, download this entire gist with `git clone https://gist.github.com/4455067.git`

 1. Get Eggdrop 1.8 [from CVS][eggcvs] or [from Git][egggit] (1.6 may work, but I have not tested it. 1.8 is better anyway – with SSL and IPv6 support.)

 2. Apply [the patch][patch] `preinit-server.patch`.

    Alternatively, you can use [my Git fork][mygit] and `git checkout` the branch `preinit`.

 3. Compile and install the patched Eggdrop.

 4. From your Eggdrop config, `source` the scripts and set the SASL information.

    ```tcl
    source "scripts/4455067/g_base64.tcl"
    source "scripts/4455067/g_cap.tcl"

    set sasl-user $username
    set sasl-pass "blahblah"

    # Let's turn off all "experimental" crap I added to g_cap
    set caps-wanted "sasl"
    ```

 5. Enjoy.

## Atheme auto-reop script:

 1. From your Eggdrop config, `source` the **g_atheme_need.tcl** script.

 2. Add a user named `services` to your bot, with ChanServ's hostmask, and give it the +fS flags.

        .+user services *!*@services.example.com
        .chattr services +fS

    Otherwise the bot can think it's being notice-flooded by ChanServ and ignore it.

[eggcvs]: http://www.eggheads.org/devel/
[egggit]: https://github.com/eggheads/eggdrop-1.8
[mygit]: https://github.com/grawity/eggdrop-1.8
[patch]: #file-preinit-server-patch