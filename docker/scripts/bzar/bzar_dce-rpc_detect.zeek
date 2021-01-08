#
# File: bzar_dce-rpc_detect.zeek
# Created: 20180701
# Updated: 20201009
#
# Copyright 2018 The MITRE Corporation.  All Rights Reserved.
# Approved for public release.  Distribution unlimited.  Case number 18-3868.
#

module BZAR;

#
# DCE-RPC Event Handlers
#

@if ((Version::info$major == 2) && (Version::info$minor <= 5))

# Use this syntax for Bro v2.5.x and below
event dce_rpc_response(c: connection, fid: count, opnum: count, stub_len: count) &priority=3
{

@else

# Use this syntax for Bro v2.6.x and above
event dce_rpc_response(c: connection, fid: count, ctx_id: count, opnum: count, stub_len: count) &priority=3
{

@endif
	# priority==3 ... We want to execute before writing to dce_rpc.log
	# because default Bro script deletes 'c$dce_rpc' after writing to log

	local rpc = "";

	#
	# Get UUID and OpNum, by Name (endpoint::operation)
	#

	if ( c?$dce_rpc && c$dce_rpc?$endpoint && c$dce_rpc?$operation )
	{
		rpc = fmt("%s::%s", c$dce_rpc$endpoint, c$dce_rpc$operation);
	}
	else
	{
		return;
	}


	# Check DCE-RPC endpoint::operation

	#
	# ATTACK::Credential_Access
	#
	if ( rpc in t1003_006_rpc_strings && t1003_006_detect_option )
	{
		# Looks like:
		# T1003.006 OS Credential Dumping: DCSync

		# Raise Notice and/or Set Observation
		BZAR::rpc_t1003_006_log(c, rpc);
	}
	#
	# ATTACK::Defense_Evasion
	#
	else if ( rpc in t1070_001_rpc_strings && t1070_001_detect_option )
	{
		# Looks like:
		# T1070.001 Indicator Removal on Host: Clear Windows Event Logs

		# Raise Notice and/or Set Observation
		BZAR::rpc_t1070_001_log(c, rpc);
	}
	#
	# ATTACK::Execution
	#
	else if ( rpc in t1569_002_rpc_strings && t1569_002_detect_option )
	{
		# Looks like:
		# T1569.002 System Services: Service Execution

		# Raise Notice and/or Set Observation
		BZAR::rpc_t1569_002_log(c, rpc);
	}
	else if ( rpc in t1047_rpc_strings && t1047_detect_option )
	{
		# Looks like:
		# T1047 WMI

		# Raise Notice and/or Set Observation
		BZAR::rpc_t1047_log(c, rpc);
	}
	else if ( rpc in t1053_002_rpc_strings && t1053_002_detect_option )
	{
		# Looks like:
		# T1053.002 Scheduled Task/Job: At

		# Raise Notice and/or Set Observation
		BZAR::rpc_t1053_002_log(c, rpc);
	}
	else if ( rpc in t1053_005_rpc_strings && t1053_005_detect_option )
	{
		# Looks like:
		# T1053.005 Scheduled Task/Job: Scheduled Task

		# Raise Notice and/or Set Observation
		BZAR::rpc_t1053_005_log(c, rpc);
	}
	#
	# ATTACK::Impact
	#
	else if ( rpc in t1529_rpc_strings && t1529_detect_option )
	{
		# Looks like:
		# T1529 System Shutdown/Reboot

		# Raise Notice and/or Set Observation
		BZAR::rpc_t1529_log(c, rpc);
	}
	#
	# ATTACK::Persistence
	#
	else if ( rpc in t1547_004_rpc_strings && t1547_004_detect_option )
	{
		# Looks like:
		# T1547.004 Boot or Logon Autostart Execution: Winlogon Helper DLL

		# Raise Notice and/or Set Observation
		BZAR::rpc_t1547_004_log(c, rpc);
	}
	else if ( rpc in t1547_010_rpc_strings && t1547_010_detect_option )
	{
		# Looks like:
		# T1547.010 Boot or Logon Autostart Execution: Port Monitors

		# Raise Notice and/or Set Observation
		BZAR::rpc_t1547_010_log(c, rpc);
	}
	#
	# ATTACK::Discovery
	#
	else if ( rpc in t1016_rpc_strings && t1016_detect_option )
	{
		# Looks like:
		# T1016 System Network Configuration Discovery

		# Raise Notice and/or Set Observation
		BZAR::rpc_t1016_log(c, rpc);
	}
	else if ( rpc in t1018_rpc_strings && t1018_detect_option )
	{
		# Looks like:
		# T1018 Remote System Discovery

		# Raise Notice and/or Set Observation
		BZAR::rpc_t1018_log(c, rpc);
	}
	else if ( rpc in t1033_rpc_strings && t1033_detect_option )
	{
		# Looks like:
		# T1033 System Owner/User Discovery

		# Raise Notice and/or Set Observation
		BZAR::rpc_t1033_log(c, rpc);
	}
	else if ( rpc in t1049_rpc_strings && t1049_detect_option )
	{
		# Looks like:
		# T1049 System Network Connections Discovery

		# Raise Notice and/or Set Observation
		BZAR::rpc_t1049_log(c, rpc);
	}
	else if ( rpc in t1069_rpc_strings && t1069_detect_option )
	{
		# Looks like:
		# T1069 Permission Groups Discovery

		# Raise Notice and/or Set Observation
		BZAR::rpc_t1069_log(c, rpc);
	}
	else if ( rpc in t1082_rpc_strings && t1082_detect_option )
	{
		# Looks like:
		# T1082 System Information Discovery

		# Raise Notice and/or Set Observation
		BZAR::rpc_t1082_log(c, rpc);
	}
	else if ( rpc in t1083_rpc_strings && t1083_detect_option )
	{
		# Looks like:
		# T1083 File and Directory Discovery

		# Raise Notice and/or Set Observation
		BZAR::rpc_t1083_log(c, rpc);
	}
	else if ( rpc in t1087_rpc_strings && t1087_detect_option )
	{
		# Looks like:
		# T1087 Account Discovery

		# Raise Notice and/or Set Observation
		BZAR::rpc_t1087_log(c, rpc);
	}
	else if ( rpc in t1124_rpc_strings && t1124_detect_option )
	{
		# Looks like:
		# T1124 System Time Discovery

		# Raise Notice and/or Set Observation
		BZAR::rpc_t1124_log(c, rpc);
	}
	else if ( rpc in t1135_rpc_strings && t1135_detect_option )
	{
		# Looks like:
		# T1135 Network Share Discovery

		# Raise Notice and/or Set Observation
		BZAR::rpc_t1135_log(c, rpc);
	}
}

#end bzar_dce-rpc_detect.zeek
