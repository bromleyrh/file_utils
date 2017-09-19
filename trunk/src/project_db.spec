#
# project_db_schema_gram.spec
#

<document> = {
    <key_definition>
    <value_definition>
}

<key_definition> = "key" : <members_definition>

<value_definition> = "value" : <members_definition>

<members_definition> = [ <member_definition>+ ]

<member_definition> = {
    <type_definition>
    <name_definition>
}

<type_definition> = "type" : <type_name>

<name_definition> = "name" : <string>

<type_name> = ( "char" | "stringz" )

# vi: set expandtab sw=4 ts=4:
