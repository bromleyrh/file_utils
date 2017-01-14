<conf> = {
    <copy_creds?>
    <debug?>
    <discard_cache?>
    <log?>
    <transfers?>
}

<copy_creds> = "copy_creds" : (<copy_uidgid> | <copy_usrgrp>)

<debug> = "debug" : <Boolean>

<discard_cache> = "discard_cache" : <Boolean>

<log> = "log" : <Boolean>

<transfers> = "transfers" : [ <transfer>+ ]

<transfer> = {
    <transfer_source>
    <transfer_destination>
    <transfer_dstpath>
    <transfer_format_cmd>
    <transfer_setro?>
}

<copy_uidgid> = {
    <uid>
    <gid>
}

<copy_usrgrp> = {
    <user>
    <group>
}

<transfer_source> = "src" : <string>

<transfer_destination> = "dest" : <string>

<transfer_dstpath> = "dstpath" : <string>

<transfer_format_cmd> = "format_cmd" : <string>

<transfer_setro> = "setro" : <Boolean>

<uid> = "uid" : <string>

<gid> = "gid" : <string>

<user> = "user" : <string>

<group> = "group" : <string>
