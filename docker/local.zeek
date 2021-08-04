##! Local site policy. Customize as appropriate.
##!
##! This file will not be overwritten when upgrading or reinstalling!

# This script logs which scripts were loaded during each run.
@load misc/loaded-scripts

# Apply the default tuning scripts for common tuning settings.
@load tuning/defaults

# Estimate and log capture loss.
@load misc/capture-loss

# Enable logging of memory, packet and lag statistics.
@load misc/stats

# Load the scan detection script.
@load misc/scan

# Detect traceroute being run on the network. This could possibly cause
# performance trouble when there are a lot of traceroutes on your network.
# Enable cautiously.
#@load misc/detect-traceroute

# Generate notices when vulnerable versions of software are discovered.
# The default is to only monitor software found in the address space defined
# as "local".  Refer to the software framework's documentation for more
# information.
@load frameworks/software/vulnerable

# Detect software changing (e.g. attacker installing hacked SSHD).
@load frameworks/software/version-changes

# This adds signatures to detect cleartext forward and reverse windows shells.
@load-sigs frameworks/signatures/detect-windows-shells

# Load all of the scripts that detect software in various protocols.
@load protocols/ftp/software
@load protocols/smtp/software
@load protocols/ssh/software
@load protocols/http/software
# The detect-webapps script could possibly cause performance trouble when
# running on live traffic.  Enable it cautiously.
@load protocols/http/detect-webapps

# This script detects DNS results pointing toward your Site::local_nets
# where the name is not part of your local DNS zone and is being hosted
# externally.  Requires that the Site::local_zones variable is defined.
@load protocols/dns/detect-external-names

# Script to detect various activity in FTP sessions.
@load protocols/ftp/detect

# Scripts that do asset tracking.
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/ssl/known-certs

# This script enables SSL/TLS certificate validation.
@load protocols/ssl/validate-certs

# This script prevents the logging of SSL CA certificates in x509.log
@load protocols/ssl/log-hostcerts-only

# Uncomment the following line to check each SSL certificate hash against the ICSI
# certificate notary service; see http://notary.icsi.berkeley.edu .
@load protocols/ssl/notary

# If you have GeoIP support built in, do some geographic detections and
# logging for SSH traffic.
#@load protocols/ssh/geo-data
# Detect hosts doing SSH bruteforce attacks.
@load protocols/ssh/detect-bruteforcing
# Detect logins using "interesting" hostnames.
@load protocols/ssh/interesting-hostnames

# Detect SQL injection attacks.
@load protocols/http/detect-sqli

#### Network File Handling ####

# Enable MD5 and SHA1 hashing for all files.
@load frameworks/files/hash-all-files

# Detect SHA1 sums in Team Cymru's Malware Hash Registry.
@load frameworks/files/detect-MHR

# Extend email alerting to include hostnames
@load policy/frameworks/notice/extend-email/hostnames

# Uncomment the following line to enable detection of the heartbleed attack. Enabling
# this might impact performance a bit.
@load policy/protocols/ssl/heartbleed

# Uncomment the following line to enable logging of connection VLANs. Enabling
# this adds two VLAN fields to the conn.log file.
@load policy/protocols/conn/vlan-logging

# Uncomment the following line to enable logging of link-layer addresses. Enabling
# this adds the link-layer address for each connection endpoint to the conn.log file.
@load policy/protocols/conn/mac-logging

# Salesforce hassh 
@load scripts/hassh

# Salesforce ja3
@load scripts/ja3

# Cybera Sniffpass
@load scripts/zeek-sniffpass 

# Corlight http post body
@load scripts/log-add-http-post-bodies

# Json Logs
@load scripts/json-logs

# Corlight CommunityID
#@load scripts/CommunityID

# add-interfaces
@load scripts/add-interfaces

# Mitre BZAR
@load scripts/bzar

# publish-community_id
@load scripts/publish-community_id


redef record Conn::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record DCE_RPC::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record DHCP::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record DNP3::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record DNS::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record FTP::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record HTTP::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record IRC::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record KRB::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record Modbus::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record Modbus::MemmapInfo += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record MySQL::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record NTLM::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record NTP::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record RADIUS::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record RDP::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record RFB::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record SIP::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record SMB::CmdInfo += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record SMB::FileInfo += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record SMB::TreeInfo += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record SMTP::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record SNMP::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record SOCKS::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record SSH::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record SSL::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record Syslog::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record Tunnel::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record Files::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record OCSP::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record PE::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record X509::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record NetControl::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record NetControl::DropInfo += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record NetControl::ShuntInfo += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record NetControl::CatchReleaseInfo += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record OpenFlow::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record Intel::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record Notice::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record Notice::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record Signatures::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record Traceroute::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record Known::CertsInfo += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record Known::HostsInfo += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record Known::ModbusInfo += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record Known::ServicesInfo += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record Software::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record Barnyard2::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record DPD::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record Unified2::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record UnknownProtocol::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record Weird::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record WeirdStats::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record Broker::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record CaptureLoss::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record Cluster::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record Config::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record LoadedScripts::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record PacketFilter::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record Log::PrintLogInfo += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record Reporter::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};

redef record Stats::Info += {
    pcap_name:    string    &default=getenv("PCAP_NAME")    &log;
    hash:    string    &default=getenv("HASH")    &log;
};



# Kafka Plugin
@load Apache/Kafka
redef Kafka::send_all_active_logs = T;
redef Kafka::tag_json = T;
redef Kafka::topic_name = getenv("TOPIC_NAME");
redef Kafka::kafka_conf = table(
    ["metadata.broker.list"] = getenv("KAFKA_BOOTSTRAP_SERVER")
);
redef Kafka::max_wait_on_shutdown = 3000;
redef Kafka::json_timestamps = JSON::TS_ISO8601;
