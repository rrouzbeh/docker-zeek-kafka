module AddInterfaces;

export {
    
    redef record Conn::Info += {
        _interface: string &optional &log;
        _node_name: string &optional &log;
    };
}

event connection_state_remove(c: connection) {
    c$conn$_interface = getenv("ZEEK_INTERFACE");
    c$conn$_node_name = getenv("ZEEK_NODE_NAME");
}