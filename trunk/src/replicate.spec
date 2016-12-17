<conf> = {
    <copy_creds?>
    <debug?>
    <transfers?>
}

<copy_creds> = "copy_creds" : (<copy_uidgid> | <copy_usrgrp>)

<debug> = "debug" : <Boolean>

<transfers> = "transfers" : [ <transfer>+ ]

<transfer> = {
    <transfer_source>
    <transfer_destination>
    <transfer_format_cmd>
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

<transfer_format_cmd> = "format_cmd" : <string>

<uid> = "uid" : <string>

<gid> = "gid" : <string>

<user> = "user" : <string>

<group> = "group" : <string>
