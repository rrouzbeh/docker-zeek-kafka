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

# Kafka Plugin
@load Apache/Kafka
redef Kafka::logs_to_send = set(Conn::LOG, HTTP::LOG, SSL::LOG, Files::LOG, DNS::LOG, Notice::LOG, RDP::LOG, SSH::LOG);
redef Kafka::kafka_conf = table(
    ["metadata.broker.list"] = getenv("KAFKA_BOOTSTRAP_SERVER")
);
redef Kafka::topic_name = "";
redef Kafka::max_wait_on_shutdown = 3000;
redef Kafka::json_timestamps = JSON::TS_ISO8601;

redef Log::default_field_name_map = {
    ["id.orig_h"] = "src_ip_addr",
    ["id.orig_p"] = "src_port",
    ["id.resp_h"] = "dst_ip_addr",
    ["id.resp_p"] = "dst_port",
    ["proto"] = "protocol",
    ["tx_hosts"] = "src_ip_addr",
    ["rx_hosts"] = "dst_ip_addr",
    ["local_orig"] = "src_is_local",
    ["local_resp"] = "dst_is_local",
    ["service"] = "service_name",
    ["orig_bytes"] = "bytes_out",
    ["orig_ip_bytes"] = "bytes_out_ip",
    ["resp_bytes"] = "bytes_in",
    ["resp_ip_bytes"] = "bytes_in_ip",
    ["missed_bytes"] = "bytes_missed",
    ["orig_pkts"] = "packets_out",
    ["resp_pkts"] = "packets_in",
    ["user_agent"] = "http_user_agent",
    ["resp_mime_types"] = "http_content_type",
    ["method"] = "http_method",
    ["referrer"] = "http_referrer",
    ["request_body_len"] = "bytes_out",
    ["response_body_len"] = "bytes_in",
    ["orig_l2_addr"] = "src_l2_addr",
    ["resp_l2_addr"] = "dst_l2_addr",
    ["community_id"] = "network_community_id",
    ["_node_name"] = "sensor_node_name",
    ["_interface"] = "sensor_interface"

    };
