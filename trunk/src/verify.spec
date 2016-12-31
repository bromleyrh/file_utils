<conf> = {
    <base_dir?>
    <creds?>
    <debug?>
    <exclude?>
    <log?>
    <output_file>
    <verifs?>
}

<base_dir> = "base_dir" : <string>

<creds> = "creds" : (<creds_uidgid> | <creds_usrgrp>)

<debug> = "debug" : <Boolean>

<exclude> = "exclude" : [ <string>+ ]

<log> = "log" : <Boolean>

<output_file> = "output_file" : <string>

<verifs> = "verifs" : [ <verif>+ ]

<verif> = {
    <verif_dev>
    <verif_source>
}

<creds_uidgid> = {
    <uid>
    <gid>
}

<creds_usrgrp> = {
    <user>
    <group>
}

<verif_dev> = "dev" : <string>

<verif_source> = "src" : <string>

<uid> = "uid" : <string>

<gid> = "gid" : <string>

<user> = "user" : <string>

<group> = "group" : <string>
