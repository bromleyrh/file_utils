#define _CONFIG_GRAM(text) #text

#define CONFIG_GRAM _CONFIG_GRAM( \
<conf> = { \
    <base_dir?> \
    <creds?> \
    <debug?> \
    <exclude?> \
    <input_file?> \
    <log?> \
    <output_file> \
    <verifs?> \
} \
\
<base_dir> = "base_dir" : <string> \
\
<creds> = "creds" : (<creds_uidgid> | <creds_usrgrp>) \
\
<debug> = "debug" : <Boolean> \
\
<exclude> = "exclude" : [ <string>+ ] \
\
<input_file> = "input_file" : <string> \
\
<log> = "log" : <Boolean> \
\
<output_file> = "output_file" : <string> \
\
<verifs> = "verifs" : [ <verif>+ ] \
\
<verif> = { \
    <verif_dev> \
    <verif_source> \
    <verif_check_cmd?> \
} \
\
<creds_uidgid> = { \
    <uid> \
    <gid> \
} \
\
<creds_usrgrp> = { \
    <user> \
    <group> \
} \
\
<verif_dev> = "dev" : <string> \
\
<verif_source> = "src" : <string> \
\
<verif_check_cmd> = "check_cmd" : <string> \
\
<uid> = "uid" : <string> \
\
<gid> = "gid" : <string> \
\
<user> = "user" : <string> \
\
<group> = "group" : <string> \
)
