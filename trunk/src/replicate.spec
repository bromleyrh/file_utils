<conf> = {
    <debug?>
    <transfers?>
}

<debug> = "debug" : <Boolean>

<transfers> = "transfers" : [ <transfer>+ ]

<transfer> = {
    <transfer_source>
    <transfer_destination>
    <transfer_format_cmd>
}

<transfer_source> = "src" : <string>

<transfer_destination> = "dest" : <string>

<transfer_format_cmd> = "format_cmd" : <string>
