module AddInterfaces;

export {
    
    redef record Conn::Info += {
        _interface: string &optional &log;
    };
}

event connection_state_remove(c: connection) {
    c$conn$_interface = getenv("ZEEK_INTERFACE");
}