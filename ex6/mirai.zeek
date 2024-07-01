event packet_contents(c: connection, contents: string)
    {
    # Mirai is over TCP only
    if (tcp != get_conn_transport_proto(c$id)) { return; }

    # TODO: Check port (destination port is telnet)

    # TODO: Check byte pattern
    if (contents[:] == "\xde\xad\xbe\xef") {
        print fmt("Detected the sample pattern for destination %s", "?");
        }
    }
