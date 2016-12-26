<conf> = {
    <base_dir?>
    <debug?>
    <log?>
    <output_file>
    <verifs?>
    <verif_creds?>
}

<base_dir> = "base_dir" : <string>

<debug> = "debug" : <Boolean>

<log> = "log" : <Boolean>

<output_file> = "output_file" : <string>

<verifs> = "verifs" : [ <verif>+ ]

<verif_creds> = "verif_creds" : (<verif_uidgid> | <verif_usrgrp>)

<verif> = {
    <verif_source>
}

<verif_uidgid> = {
    <uid>
    <gid>
}

<verif_usrgrp> = {
    <user>
    <group>
}

<verif_source> = "src" : <string>

<uid> = "uid" : <string>

<gid> = "gid" : <string>

<user> = "user" : <string>

<group> = "group" : <string>
