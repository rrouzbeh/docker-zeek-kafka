#
# File: bzar_dce-rpc_consts.zeek
# Created: 20180701
# Updated: 20201009
#
# Copyright 2018 The MITRE Corporation.  All Rights Reserved.
# Approved for public release.  Distribution unlimited.  Case number 18-3868.
#

module BZAR;

export
{
	# ATT&CK - Credential Access Techniques
	#
	# Windows DCE-RPC functions (endpoint::operation) used for
	# Credential Access on the remote system
	# 
	# Relevant ATT&CK Technique(s):
	#    T1003.006 OS Credential Dumping: DCSync

	const t1003_006_rpc_strings : set[string] =
	{
		# T1003.006 OS Credential Dumping: DCSync
		["drsuapi::DRSReplicaSync"],
		["drsuapi::DRSGetNCChanges"],
	} &redef;


	# ATT&CK - Defense Evasion Techniques
	#
	# Windows DCE-RPC functions (endpoint::operation) used for
	# Defense Evasion on the remote system
	# 
	# Relevant ATT&CK Technique(s):
	#    T1070.001 Indicator Removal on Host: Clear Windows Event Logs

	const t1070_001_rpc_strings : set[string] =
	{
		# T1070.001 Indicator Removal on Host
		# Clear Event Logs
		["eventlog::ElfrClearELFW"],
		["eventlog::ElfrClearELFA"],
		["IEventService::EvtRpcClearLog"],
	} &redef;


	# ATT&CK - Execution Techniques
	#
	# Windows DCE-RPC functions (endpoint::operation) used for 
	# Execution on the remote system
	# 
	# Relevant ATT&CK Technique(s):
	#    T1569.002 System Services: Service Execution
	#    T1047 Windows Management Instrumentation
	#    T1053.002 Scheduled Task/Job: At
	#    T1053.005 Scheduled Task/Job: Scheduled Task

	const t1569_002_rpc_strings : set[string] = 
	{
		# T1569.002 System Services: Service Execution
		["svcctl::CreateServiceWOW64W"],
		["svcctl::CreateServiceWOW64A"],
		["svcctl::CreateServiceW"],
		["svcctl::CreateServiceA"],
		["svcctl::StartServiceW"],
		["svcctl::StartServiceA"],
	} &redef;

	const t1047_rpc_strings : set[string] = 
	{
		# T1047 Windows Management Instrumentation
		["IWbemServices::ExecMethod"],
		["IWbemServices::ExecMethodAsync"],
	} &redef;

	const t1053_002_rpc_strings : set[string] =
	{
		# T1053.002 Scheduled Task/Job: At
		["atsvc::JobAdd"],
	} &redef;

	const t1053_005_rpc_strings : set[string] =
	{
		# T1053.005 Scheduled Task/Job: Scheduled Task
		["ITaskSchedulerService::SchRpcRegisterTask"],
		["ITaskSchedulerService::SchRpcRun"],
		["ITaskSchedulerService::SchRpcEnableTask"],
	} &redef;


	# ATT&CK - Impact Techniques
	#
	# Windows DCE-RPC functions (endpoint::operation) used for
	# Impact on the remote system
	# 
	# Relevant ATT&CK Technique(s):
	#    T1529 System Shutdown/Reboot

	const t1529_rpc_strings : set[string] =
	{
		# T1529 System Shutdown/Reboot
		["winreg::BaseInitiateSystemShutdown"],
		["winreg::BaseInitiateSystemShutdownEx"],
		["InitShutdown::BaseInitiateShutdown"],
		["InitShutdown::BaseInitiateShutdownEx"],
		["WindowsShutdown::WsdrInitiateShutdown"],
		["winstation_rpc::RpcWinStationShutdownSystem"],
		["samr::SamrShutdownSamServer"], # MSDN says not used on the wire
	} &redef;


	# ATT&CK - Persistence Techniques
	#
	# Windows DCE-RPC functions (endpoint::operation) used for
	# Persistence on the remote system
	# 
	# Relevant ATT&CK Technique(s):
	#    T1547.004 Boot or Logon Autostart Execution: Winlogon Helper DLL
	#    T1547.010 Boot or Logon Autostart Execution: Port Monitors

	const t1547_004_rpc_strings : set[string] = 
	{
		# T1547.004 Boot or Logon Autostart Execution: Winlogon Helper DLL
		["ISecLogon::SeclCreateProcessWithLogonW"],
		["ISecLogon::SeclCreateProcessWithLogonExW"],
	} &redef;

	const t1547_010_rpc_strings : set[string] = 
	{
		# T1547.010 Boot or Logon Autostart Execution: Port Monitors
		["spoolss::RpcAddMonitor"],		# aka winspool | spoolss
		["spoolss::RpcAddPrintProcessor"],	# aka winspool | spool
		["IRemoteWinspool::RpcAsyncAddMonitor"],
		["IRemoteWinspool::RpcAsyncAddPrintProcessor"],
	} &redef;


	# ATT&CK - Discovery Techniques
	#
	# Windows DCE-RPC functions (endpoint::operation) used for
	# Discovery of users, hosts, files, shares, networks, time
	#
	# Relevant ATT&CK Technique(s):
	#    T1016 System Network Configuration Discovery
	#    T1018 Remote System Discovery 
	#    T1033 System Owner/User Discovery 
	#    T1049 System Network Connections Discovery
	#    T1069 Permission Groups Discovery 
	#    T1082 System Information Discovery
	#    T1083 File & Directory Discovery
	#    T1087 Account Discovery
	#    T1124 System Time Discovery
	#    T1135 Network Share Discovery

	const t1016_rpc_strings : set[string] =
	{
		# T1016 System Network Configuration Discovery
		["srvsvc::NetrServerTransportEnum"],
		["wkssvc::NetrWkstaTransportEnum"],
	} &redef;

	const t1018_rpc_strings : set[string] =
	{
		# T1018 Remote System Discovery 
		["srvsvc::NetrServerGetInfo"],
		["srvsvc::NetrServerAliasEnum"],
		["wkssvc::NetrWkstaGetInfo"],
	} &redef;

	const t1033_rpc_strings : set[string] =
	{
		# T1033 System Owner/User Discovery 
		["lsarpc::LsarGetUserName"],
		["lsarpc::LsarEnumerateTrustedDomainsEx"],
		["lsarpc::LsarGetSystemAccessAccount"],

		["lsarpc::LsarQueryDomainInformationPolicy"],
		["lsarpc::LsarQueryInfoTrustedDomain"],

		["samr::SamrEnumerateGroupsInDomain"],
		["samr::SamrEnumerateDomainsInSamServer"],

		["samr::SamrQueryInformationDomain"],
		["samr::SamrQueryInformationDomain2"],
		["samr::SamrQueryInformationGroup"],
	} &redef;

	const t1049_rpc_strings : set[string] =
	{
		# T1049 System Network Connections Discovery
		["srvsvc::NetrConnectionEnum"],
		["srvsvc::NetrSessionEnum"],
	} &redef;

	const t1069_rpc_strings : set[string] =
	{
		# T1069 Permission Groups Discovery 
		["lsarpc::LsarEnumerateAccountRights"],
		["lsarpc::LsarEnumerateAccountsWithUserRight"],
		["lsarpc::LsarEnumeratePrivileges"],
		["lsarpc::LsarEnumeratePrivilegesAccount"],
		["lsarpc::LsarLookupPrivilegeValue"],
		["lsarpc::LsarLookupPrivilegeName"],
		["lsarpc::LsarLookupPrivilegeDisplayName"],

		["samr::SamrGetGroupsForUser"],
		["samr::SamrGetAliasMembership"],
		["samr::SamrGetMembersInAlias"],
		["samr::SamrGetMembersInGroup"],
	} &redef;

	const t1082_rpc_strings : set[string] =
	{
		# T1082 System Information Discovery
		["lsarpc::LsarQueryInformationPolicy"],
		["lsarpc::LsarQueryInformationPolicy2"],
		["lsarpc::LsarQueryTrustedDomainInfo"],
		["lsarpc::LsarQueryTrustedDomainInfoByName"],

		["samr::SamrGetUserDomainPasswordInformation"],
	} &redef;

	const t1083_rpc_strings : set[string] =
	{
		# T1083 File & Directory Discovery
		["srvsvc::NetrFileEnum"],
	} &redef;

	const t1087_rpc_strings : set[string] =
	{
		# T1087 Account Discovery
		["lsarpc::LsarEnumerateAccounts"],
		["lsarpc::LsarLookupNames"],
		["lsarpc::LsarLookupNames2"],
		["lsarpc::LsarLookupNames3"],
		["lsarpc::LsarLookupNames4"],
		["lsarpc::LsarLookupSids"],
		["lsarpc::LsarLookupSids2"],
		["lsarpc::LsarLookupSids3"],

		["samr::SamrEnumerateAliasesInDomain"],
		["samr::SamrEnumerateUsersInDomain"],
		["samr::SamrLookupNamesInDomain"],
		["samr::SamrLookupIdsInDomain"],
		["samr::SamrLookupDomainInSamServer"],
		["samr::SamrQueryDisplayInformation"],
		["samr::SamrQueryDisplayInformation2"],
		["samr::SamrQueryDisplayInformation3"],
		["samr::SamrQueryInformationAlias"],
		["samr::SamrQueryInformationUser"],
		["samr::SamrQueryInformationUser2"],

		["wkssvc::NetrWkstaUserEnum"],
	} &redef;

	const t1124_rpc_strings : set[string] =
	{
		# T1124 System Time Discovery
		["srvsvc::NetrRemoteTOD"],
	} &redef;

	const t1135_rpc_strings : set[string] =
	{
		# T1135 Network Share Discovery
		["srvsvc::NetrShareEnum"],
		["srvsvc::NetrShareGetInfo"],
	} &redef;


	# Microsoft DCE-RPC Interface UUIDs (aka "endpoints") -- 144 more --
	# to add to Bro DCE_RPC::uuid_endpoint_map.
	#
	# References:
	#     MSDN Library > Open Specifications > Protocols > Windows Protocols > Technical Documents
	#     https://msdn.microsoft.com/en-us/library/jj712081.aspx

	redef DCE_RPC::uuid_endpoint_map +=
	{
		["0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7"] = "authzr",
		["e3d0d746-d2af-40fd-8a7a-0d7078bb7092"] = "BitsPeerAuth",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f"] = "clusapi",
		["d61a27c6-8f53-11d0-bfa0-00a024151983"] = "CNtmsSvr",
		["6bffd098-a112-3610-9833-46c3f874532d"] = "dhcpsrv",
		["5b821720-f63b-11d0-aad2-00c04fc324db"] = "dhcpsrv2",
		["8f09f000-b7ed-11ce-bbd2-00001a181cad"] = "dimsvc",
		["7c44d7d4-31d5-424c-bd5e-2b3e1f323d22"] = "dsaop",
		["77df7a80-f298-11d0-8358-00a024c480a8"] = "dscomm",
		["708cca10-9569-11d1-b2a5-0060977d8118"] = "dscomm2",
		["df1941c5-fe89-4e79-bf10-463657acf44d"] = "efsrpc",
		["c681d488-d850-11d0-8c52-00c04fd90f7e"] = "efsrpc2",
		["ea0a3165-4834-11d2-a6f8-00c04fa346cc"] = "fax",
		["6099fc12-3eff-11d0-abd0-00c04fd91a4e"] = "faxclient",
		["a8e0653c-2744-4389-a61d-7373df8b2292"] = "FileServerVssAgent",
		["897e2e5f-93f3-4376-9c9c-fd2277495c27"] = "FrsTransport",
		["4bb8ab1d-9ef9-4100-8eb6-dd4b4e418b72"] = "IADProxy",
		["c4b0c7d9-abe0-4733-a1e1-9fdedf260c7a"] = "IADProxy2",
		["03837516-098b-11d8-9414-505054503030"] = "IAlertDataCollector",
		["0383751a-098b-11d8-9414-505054503030"] = "IApiTracingDataCollector",
		["d99e6e71-fc88-11d0-b498-00a0c90312f3"] = "ICertAdminD",
		["7fe0d935-dda6-443f-85d0-1cfb58fe41dd"] = "ICertAdminD2",
		["d99e6e70-fc88-11d0-b498-00a0c90312f3"] = "ICertRequestD",
		["5422fd3a-d4b8-4cef-a12e-e87d4ca22e90"] = "ICertRequestD2",
		["879c8bbe-41b0-11d1-be11-00c04fb6bf70"] = "IClientSink",
		["03837514-098b-11d8-9414-505054503030"] = "IConfigurationDataCollector",
		["038374ff-098b-11d8-9414-505054503030"] = "IDataCollector",
		["03837502-098b-11d8-9414-505054503030"] = "IDataCollectorCollection",
		["03837520-098b-11d8-9414-505054503030"] = "IDataCollectorSet",
		["03837524-098b-11d8-9414-505054503030"] = "IDataCollectorSetCollection",
		["03837541-098b-11d8-9414-505054503030"] = "IDataManager",
		["00020400-0000-0000-c000-000000000046"] = "IDispatch",
		["d2d79df7-3400-11d0-b40b-00aa005ff586"] = "IDMNotify",
		["3a410f21-553f-11d1-8e5e-00a0c92c9d5d"] = "IDMRemoteServer",
		["00020404-0000-0000-c000-000000000046"] = "IEnumVARIANT",
		["027947e1-d731-11ce-a357-000000000001"] = "IEnumWbemClassObject",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c"] = "IEventService",
		["03837543-098b-11d8-9414-505054503030"] = "IFolderAction",
		["03837544-098b-11d8-9414-505054503030"] = "IFolderActionCollection",
		["7c4e1804-e342-483d-a43e-a850cfcc8d18"] = "IIISApplicationAdmin",
		["bd0c73bc-805b-4043-9c30-9a28d64dd7d2"] = "IIISCertObj",
		["e8fb8620-588f-11d2-9d61-00c04f79c5fe"] = "IIisServiceControl",
		["c3fcc19e-a970-11d2-8b5a-00a0c9b7c9c4"] = "IManagedObject",
		["034634fd-ba3f-11d1-856a-00a0c944138c"] = "IManageTelnetSessions",
		["081e7188-c080-4ff3-9238-29f66d6cabfd"] = "IMessenger",
		["8298d101-f992-43b7-8eca-5052d885b995"] = "IMSAdminBase2W",
		["f612954d-3b0b-4c56-9563-227b7be624b4"] = "IMSAdminBase3W",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750"] = "IMSAdminBaseW",
		["82ad4280-036b-11cf-972c-00aa006887b0"] = "inetinfo",
		["4e934f30-341a-11d1-8fb1-00a024cb6019"] = "INtmsLibraryControl1",
		["db90832f-6910-4d46-9f5e-9fd6bfa73903"] = "INtmsLibraryControl2",
		["d02e4be0-3419-11d1-8fb1-00a024cb6019"] = "INtmsMediaServices1",
		["bb39332c-bfee-4380-ad8a-badc8aff5bb6"] = "INtmsNotifySink",
		["69ab7050-3059-11d1-8faf-00a024cb6019"] = "INtmsObjectInfo1",
		["b057dc50-3059-11d1-8faf-00a024cb6019"] = "INtmsObjectManagement1",
		["895a2c86-270d-489d-a6c0-dc2a9b35280e"] = "INtmsObjectManagement2",
		["3bbed8d9-2c9a-4b21-8936-acb2f995be6c"] = "INtmsObjectManagement3",
		["8da03f40-3419-11d1-8fb1-00a024cb6019"] = "INtmsSession1",
		["784b693d-95f3-420b-8126-365c098659f2"] = "IOCSPAdminD",
		["833e4100-aff7-4ac3-aac2-9f24c1457bce"] = "IPCHCollection",
		["833e4200-aff7-4ac3-aac2-9f24c1457bce"] = "IPCHService",
		["03837506-098b-11d8-9414-505054503030"] = "IPerformanceCounterDataCollector",
		["f120a684-b926-447f-9df4-c966cb785648"] = "IRASrv",
		["6619a740-8154-43be-a186-0319578e02db"] = "IRemoteDispatch",
		["66a2db22-d706-11d0-a37b-00c04fc9da04"] = "IRemoteICFICSConfig",
		["6139d8a4-e508-4ebb-bac7-d7f275145897"] = "IRemoteIPV6Config",
		["66a2db1b-d706-11d0-a37b-00c04fc9da04"] = "IRemoteNetworkConfig",
		["66a2db20-d706-11d0-a37b-00c04fc9da04"] = "IRemoteRouterRestart",
		["66a2db21-d706-11d0-a37b-00c04fc9da04"] = "IRemoteSetDnsConfig",
		["5ff9bdf6-bd91-4d8b-a614-d6317acc8dd8"] = "IRemoteSstpCertCheck",
		["67e08fc2-2984-4b62-b92e-fc1aae64bbbb"] = "IRemoteStringIdConfig",
		["00000131-0000-0000-c000-000000000046"] = "IRemUnknown",
		["c5cebee2-9df5-4cdd-a08c-c2471bc144b4"] = "IResourceManager",
		["2a3eb639-d134-422d-90d8-aaa1b5216202"] = "IResourceManager2",
		["7d07f313-a53f-459a-bb12-012c15b1846e"] = "IRobustNtmsMediaServices1",
		["833e41aa-aff7-4ac3-aac2-9f24c1457bce"] = "ISAFSession",
		["0383753a-098b-11d8-9414-505054503030"] = "ISchedule",
		["0383753d-098b-11d8-9414-505054503030"] = "IScheduleCollection",
		["b9785960-524f-11df-8b6d-83dcded72085"] = "ISDKey",
		["e65e8028-83e8-491b-9af7-aaf6bd51a0ce"] = "IServerHealthReport",
		["20d15747-6c48-4254-a358-65039fd8c63c"] = "IServerHealthReport2",
		["8165b19e-8d3a-4d0b-80c8-97de310db583"] = "IServicedComponentInfo",
		["112b1dff-d9dc-41f7-869f-d67fee7cb591"] = "ITpmVirtualSmartCardManager",
		["fdf8a2b9-02de-47f4-bc26-aa85ab5e5267"] = "ITpmVirtualSmartCardManager2",
		["3c745a97-f375-4150-be17-5950f694c699"] = "ITpmVirtualSmartCardManager3",
		["1a1bb35f-abb8-451c-a1ae-33d98f1bef4a"] = "ITpmVirtualSmartCardManagerStatusCallback",
		["0383750b-098b-11d8-9414-505054503030"] = "ITraceDataCollector",
		["03837512-098b-11d8-9414-505054503030"] = "ITraceDataProvider",
		["03837510-098b-11d8-9414-505054503030"] = "ITraceDataProviderCollection",
		["00020403-0000-0000-c000-000000000046"] = "ITypeComp",
		["00020401-0000-0000-c000-000000000046"] = "ITypeInfo",
		["00020412-0000-0000-c000-000000000046"] = "ITypeInfo2",
		["00020402-0000-0000-c000-000000000046"] = "ITypeLib",
		["00020411-0000-0000-c000-000000000046"] = "ITypeLib2",
		["00000000-0000-0000-c000-000000000046"] = "IUnknown",
		["03837534-098b-11d8-9414-505054503030"] = "IValueMap",
		["03837533-098b-11d8-9414-505054503030"] = "IValueMapItem",
		["d2d79df5-3400-11d0-b40b-00aa005ff586"] = "IVolumeClient",
		["4bdafc52-fe6a-11d2-93f8-00105a11164a"] = "IVolumeClient2",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61"] = "IVolumeClient3",
		["deb01010-3a37-4d26-99df-e2bb6ae3ac61"] = "IVolumeClient4",
		["214a0f28-b737-4026-b847-4f9e37d79529"] = "IVssDifferentialSoftwareSnapshotMgmt",
		["01954e6b-9254-4e6e-808c-c9e05d007696"] = "IVssEnumMgmtObject",
		["ae1c7110-2f60-11d3-8a39-00c04f72d8e3"] = "IVssEnumObject",
		["fa7df749-66e7-4986-a27f-e2f04ae53772"] = "IVssSnapshotMgmt",
		["29822ab7-f302-11d0-9953-00c04fd919c1"] = "IWamAdmin",
		["29822ab8-f302-11d0-9953-00c04fd919c1"] = "IWamAdmin2",
		["4f7ca01c-a9e5-45b6-b142-2332a1339c1d"] = "IWRMAccounting",
		["481e06cf-ab04-4498-8ffe-124a0a34296d"] = "IWRMCalendar",
		["21546ae8-4da5-445e-987f-627fea39c5e8"] = "IWRMConfig",
		["943991a5-b3fe-41fa-9696-7f7b656ee34b"] = "IWRMMachineGroup",
		["59602eb6-57b0-4fd8-aa4b-ebf06971fe15"] = "IWRMPolicy",
		["f31931a9-832d-481c-9503-887a0e6a79f0"] = "IWRMProtocol",
		["fc910418-55ca-45ef-b264-83d4ce7d30e0"] = "IWRMRemoteSessionMgmt",
		["bc681469-9dd9-4bf4-9b3d-709f69efe431"] = "IWRMResourceGroup",
		["e33c0cc4-0482-101a-bc0c-02608c6ba218"] = "locator",
		["afc07e2e-311c-4435-808c-c483ffeec7c9"] = "lsacap",
		["22e5386d-8b12-4bf0-b0ec-6a1ea419e366"] = "NetEventForwarder",
		["d049b186-814f-11d1-9a3c-00c04fc9b232"] = "NtFrsApi",
		["da5a86c5-12c2-4943-ab30-7f74a813d853"] = "PerflibV2",
		["1088a980-eae5-11d0-8d9b-00a02453c337"] = "qm2qm",
		["fdb3a030-065f-11d1-bb9b-00a024ea5525"] = "qmcomm",
		["76d12b80-3467-11d3-91ff-0090272f9ea3"] = "qmcomm2",
		["41208ee0-e970-11d1-9b9e-00e02c064c39"] = "qmmgmt",
		["20610036-fa22-11cf-9823-00a0c911e5df"] = "rasrpc",
		["497d95a6-2d27-4bf5-9bbd-a6046957133c"] = "RCMListener",
		["bde95fdf-eee0-45de-9e12-e5a61cd0d4fe"] = "RCMPublic",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48"] = "RemoteFW",
		["1a9134dd-7b39-45ba-ad88-44d01ca47f28"] = "RemoteRead",
		["2f5f6521-ca47-1068-b319-00dd010662db"] = "remotesp",
		["1257b580-ce2f-4109-82d6-a9459d0bf6bc"] = "SessEnvPublicRpc",
		["4b112204-0e19-11d3-b42b-0000f81feb9f"] = "ssdpsrv",
		["2f5f6520-ca46-1067-b319-00dd010662da"] = "tapsrv",
		["88143fd0-c28d-4b2b-8fef-8d882f6a9390"] = "TermServEnumeration",
		["11899a43-2b68-4a76-92e3-a3d6ad8c26ce"] = "TermServNotification",
		["484809d6-4239-471b-b5bc-61df8c23ac48"] = "TermSrvSession",
		["4da1c422-943d-11d1-acae-00c04fc2aa3f"] = "trksvr",
		["300f3532-38cc-11d0-a3f0-0020af6b0add"] = "trkwks",
		["44e265dd-7daf-42cd-8560-3cdb6e7a2729"] = "TsProxyRpcInterface",
		["53b46b02-c73b-4a3e-8dee-b16b80672fc0"] = "TSVIPPublic",
		["8fb6d884-2388-11d0-8c35-00c04fda2795"] = "W32Time",
		["1a927394-352e-4553-ae3f-7cf4aafca620"] = "WdsRpcInterface",
		["811109bf-a4e1-11d1-ab54-00a0c91e9b45"] = "winsi2",
		["ccd8c074-d0e5-4a40-92b4-d074faa6ba28"] = "Witness",
	} &redef;


	# Microsoft DCE-RPC Interface Methods (aka "operations") -- 1,145 more --
	# to add to Bro DCE_RPC::operations.
	#
	# References:
	#    MSDN Library > Open Specifications > Protocols > Windows Protocols > Technical Documents
	#    https://msdn.microsoft.com/en-us/library/jj712081.aspx
	#
	#    Marchand, Windows Network Services Internals [2006]
	#    http://index-of.es/Windows/win_net_srv.pdf

	redef DCE_RPC::operations +=
	{
		# authzr - MSDN Ref: Remote Authorization API Protocol [ms-raa]
		["0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7",0x00] = "AuthzrFreeContext",
		["0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7",0x01] = "AuthzrInitializeContextFromSid",
		["0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7",0x02] = "AuthrzInitializeCompoundContext",
		["0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7",0x03] = "AuthrzAccessCheck",
		["0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7",0x04] = "AuthrzGetInformationFromContext",
		["0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7",0x05] = "AuthrzModifyClaims",
		["0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7",0x06] = "AuthrzModifySids",

		# BitsPeerAuth - MSDN Ref: BITS Peer-Caching: Peer Authentication Protocol [ms-bpau]
		["e3d0d746-d2af-40fd-8a7a-0d7078bb7092",0x00] = "ExchangePublicKeys",

		# clusapi (v2) - MSDN Ref: Failover Cluster Mgmt API Protocol [ms-cmrp]
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x00] = "ApiOpenCluster",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x01] = "ApiCloseCluster",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x02] = "ApiSetClusterName",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x03] = "ApiGetClusterName",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x04] = "ApiGetClusterVersion",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x05] = "ApiGetQuorumResource",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x06] = "ApiSetQuorumResource",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x07] = "ApiCreateEnum",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x08] = "ApiOpenResource",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x09] = "ApiCreateResource",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x0A] = "ApiDeleteResource",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x0B] = "ApiCloseResource",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x0C] = "ApiGetResourceState",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x0D] = "ApiSetResourceName",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x0E] = "ApiGetResourceId",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x0F] = "ApiGetResourceType",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x10] = "ApiFailResource",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x11] = "ApiOnlineResource",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x12] = "ApiOfflineResource",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x13] = "ApiAddResourceDependency",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x14] = "ApiRemoveResourceDependency",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x15] = "ApiCanResourceBeDependent",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x16] = "ApiCreateResEnum",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x17] = "ApiAddResourceNode",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x18] = "ApiRemoveResourceNode",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x19] = "ApiChangeResourceGroup",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x1A] = "ApiCreateResourceType",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x1B] = "ApiDeleteResourceType",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x1C] = "ApiGetRootKey",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x1D] = "ApiCreateKey",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x1E] = "ApiOpenKey",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x1F] = "ApiEnumKey",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x20] = "ApiSetValue",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x21] = "ApiDeleteValue",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x22] = "ApiQueryValue",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x23] = "ApiDeleteKey",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x24] = "ApiEnumValue",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x25] = "ApiCloseKey",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x26] = "ApiQueryInfoKey",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x27] = "ApiSetKeySecurity",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x28] = "ApiGetKeySecurity",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x29] = "ApiOpenGroup",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x2A] = "ApiCreateGroup",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x2B] = "ApiDeleteGroup",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x2C] = "ApiCloseGroup",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x2D] = "ApiGetGroupState",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x2E] = "ApiSetGroupName",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x2F] = "ApiGetGroupId",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x30] = "ApiGetNodeId",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x31] = "ApiOnlineGroup",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x32] = "ApiOfflineGroup",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x33] = "ApiMoveGroup",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x34] = "ApiMoveGroupToNode",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x35] = "ApiCreateGroupResourceEnum",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x36] = "ApiSetGroupNodeList",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x37] = "ApiCreateNotify",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x38] = "ApiCloseNotify",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x39] = "ApiAddNotifyCluster",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x3A] = "ApiAddNotifyNode",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x3B] = "ApiAddNotifyGroup",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x3C] = "ApiAddNotifyResource",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x3D] = "ApiAddNotifyKey",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x3E] = "ApiReAddNotifyNode",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x3F] = "ApiReAddNotifyGroup",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x40] = "ApiReAddNotifyResource",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x41] = "ApiGetNotify",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x42] = "ApiOpenNode",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x43] = "ApiCloseNode",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x44] = "ApiGetNodeState",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x45] = "ApiPauseNode",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x46] = "ApiResumeNode",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x47] = "ApiEvictNode",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x48] = "ApiNodeResourceControl",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x49] = "ApiResourceControl",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x4A] = "ApiNodeResourceTypeControl",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x4B] = "ApiResourceTypeControl",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x4C] = "ApiNodeGroupControl",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x4D] = "ApiGroupControl",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x4E] = "ApiNodeNodeControl",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x4F] = "ApiNodeControl",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x50] = "Opnum80NotUsedOnWire",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x51] = "ApiOpenNetwork",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x52] = "ApiCloseNetwork",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x53] = "ApiGetNetworkState",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x54] = "ApiSetNetworkName",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x55] = "ApiCreateNetworkEnum",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x56] = "ApiGetNetworkId",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x57] = "ApiSetNetworkPriorityOrder",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x58] = "ApiNodeNetworkControl",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x59] = "ApiNetworkControl",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x5A] = "ApiAddNotifyNetwork",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x5B] = "ApiReAddNotifyNetwork",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x5C] = "ApiOpenNetInterface",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x5D] = "ApiCloseNetInterface",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x5E] = "ApiGetNetInterfaceState",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x5F] = "ApiGetNetInterface",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x60] = "ApiGetNetInterfaceId",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x61] = "ApiNodeNetInterfaceControl",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x62] = "ApiNetInterfaceControl",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x63] = "ApiAddNotifyNetInterface",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x64] = "ApiReAddNotifyNetInterface",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x65] = "ApiCreateNodeEnum",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x66] = "ApiGetClusterVersion2",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x67] = "ApiCreateResTypeEnum",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x68] = "ApiBackupClusterDatabase",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x69] = "ApiNodeClusterControl",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x6A] = "ApiClusterControl",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x6B] = "ApiUnblockGetNotifyCall",
		["b97db8b2-4c63-11cf-bff6-08002be23f2f",0x6C] = "ApiSetServiceAccountPassword",

		# dhcpsrv - MSDN Ref: DHCP Server Mgmt Protocol [ms-dhcpm]
		["6bffd098-a112-3610-9833-46c3f874532d",0x00] = "R_DhcpCreateSubnet",
		["6bffd098-a112-3610-9833-46c3f874532d",0x01] = "R_DhcpSetSubnetInfo",
		["6bffd098-a112-3610-9833-46c3f874532d",0x02] = "R_DhcpGetSubnetInfo",
		["6bffd098-a112-3610-9833-46c3f874532d",0x03] = "R_DhcpEnumSubnets",
		["6bffd098-a112-3610-9833-46c3f874532d",0x04] = "R_DhcpAddSubnetElement",
		["6bffd098-a112-3610-9833-46c3f874532d",0x05] = "R_DhcpEnumSubnetElements",
		["6bffd098-a112-3610-9833-46c3f874532d",0x06] = "R_DhcpRemoveSubnetElement",
		["6bffd098-a112-3610-9833-46c3f874532d",0x07] = "R_DhcpDeleteSubnet",
		["6bffd098-a112-3610-9833-46c3f874532d",0x08] = "R_DhcpCreateOption",
		["6bffd098-a112-3610-9833-46c3f874532d",0x09] = "R_DhcpSetOptionInfo",
		["6bffd098-a112-3610-9833-46c3f874532d",0x0A] = "R_DhcpGetOptionInfo",
		["6bffd098-a112-3610-9833-46c3f874532d",0x0B] = "R_DhcpRemoveOption",
		["6bffd098-a112-3610-9833-46c3f874532d",0x0C] = "R_DhcpSetOptionValue",
		["6bffd098-a112-3610-9833-46c3f874532d",0x0D] = "R_DhcpGetOptionValue",
		["6bffd098-a112-3610-9833-46c3f874532d",0x0E] = "R_DhcpEnumOptionValues",
		["6bffd098-a112-3610-9833-46c3f874532d",0x0F] = "R_DhcpRemoveOptionValue",
		["6bffd098-a112-3610-9833-46c3f874532d",0x10] = "R_DhcpCreateClientInfo",
		["6bffd098-a112-3610-9833-46c3f874532d",0x11] = "R_DhcpSetClientInfo",
		["6bffd098-a112-3610-9833-46c3f874532d",0x12] = "R_DhcpGetClientInfo",
		["6bffd098-a112-3610-9833-46c3f874532d",0x13] = "R_DhcpDeleteClientInfo",
		["6bffd098-a112-3610-9833-46c3f874532d",0x14] = "R_DhcpEnumSubnetClients",
		["6bffd098-a112-3610-9833-46c3f874532d",0x15] = "R_DhcpGetClientOptions",
		["6bffd098-a112-3610-9833-46c3f874532d",0x16] = "R_DhcpGetMibInfo",
		["6bffd098-a112-3610-9833-46c3f874532d",0x17] = "R_DhcpEnumOptions",
		["6bffd098-a112-3610-9833-46c3f874532d",0x18] = "R_DhcpSetOptionValues",
		["6bffd098-a112-3610-9833-46c3f874532d",0x19] = "R_DhcpServerSetConfig",
		["6bffd098-a112-3610-9833-46c3f874532d",0x1A] = "R_DhcpServerGetConfig",
		["6bffd098-a112-3610-9833-46c3f874532d",0x1B] = "R_DhcpScanDatabase",
		["6bffd098-a112-3610-9833-46c3f874532d",0x1C] = "R_DhcpGetVersion",
		["6bffd098-a112-3610-9833-46c3f874532d",0x1D] = "R_DhcpAddSubnetElementV4",
		["6bffd098-a112-3610-9833-46c3f874532d",0x1E] = "R_DhcpEnumSubnetElementsV4",
		["6bffd098-a112-3610-9833-46c3f874532d",0x1F] = "R_DhcpRemoveSubnetElementV4",
		["6bffd098-a112-3610-9833-46c3f874532d",0x20] = "R_DhcpCreateClientInfoV4",
		["6bffd098-a112-3610-9833-46c3f874532d",0x21] = "R_DhcpSetClientInfoV4",
		["6bffd098-a112-3610-9833-46c3f874532d",0x22] = "R_DhcpGetClientInfoV4",
		["6bffd098-a112-3610-9833-46c3f874532d",0x23] = "R_DhcpEnumSubnetClientsV4",
		["6bffd098-a112-3610-9833-46c3f874532d",0x24] = "R_DhcpSetSuperScopeV4",
		["6bffd098-a112-3610-9833-46c3f874532d",0x25] = "R_DhcpGetSuperScopeInfoV4",
		["6bffd098-a112-3610-9833-46c3f874532d",0x26] = "R_DhcpDeleteSuperScopeV4",
		["6bffd098-a112-3610-9833-46c3f874532d",0x27] = "R_DhcpServerSetConfigV4",
		["6bffd098-a112-3610-9833-46c3f874532d",0x28] = "R_DhcpServerGetConfigV4",
		["6bffd098-a112-3610-9833-46c3f874532d",0x29] = "R_DhcpServerSetConfigVQ",
		["6bffd098-a112-3610-9833-46c3f874532d",0x2A] = "R_DhcpServerGetConfigVQ",
		["6bffd098-a112-3610-9833-46c3f874532d",0x2B] = "R_DhcpGetMibInfoVQ",
		["6bffd098-a112-3610-9833-46c3f874532d",0x2C] = "R_DhcpCreateClientInfoVQ",
		["6bffd098-a112-3610-9833-46c3f874532d",0x2D] = "R_DhcpSetClientInfoVQ",
		["6bffd098-a112-3610-9833-46c3f874532d",0x2E] = "R_DhcpGetClientInfoVQ",
		["6bffd098-a112-3610-9833-46c3f874532d",0x2F] = "R_DhcpEnumSubnetClientsVQ",
		["6bffd098-a112-3610-9833-46c3f874532d",0x30] = "R_DhcpCreateSubnetVQ",
		["6bffd098-a112-3610-9833-46c3f874532d",0x31] = "R_DhcpGetSubnetInfoVQ",
		["6bffd098-a112-3610-9833-46c3f874532d",0x32] = "R_DhcpSetSubnetInfoVQ",

		# dhcpsrv2 - MSDN Ref: DHCP Server Mgmt Protocol [ms-dhcpm]
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x00] = "R_DhcpEnumSubnetClientsV5",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x01] = "R_DhcpSetMScopeInfo",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x02] = "R_DhcpGetMScopeInfo",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x03] = "R_DhcpEnumMScopes",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x04] = "R_DhcpAddMScopeElement",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x05] = "R_DhcpEnumMScopeElements",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x06] = "R_DhcpRemoveMScopeElement",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x07] = "R_DhcpDeleteMScope",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x08] = "R_DhcpScanMDatabase",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x09] = "R_DhcpCreateMClientInfo",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x0A] = "R_DhcpSetMClientInfo",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x0B] = "R_DhcpGetMClientInfo",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x0C] = "R_DhcpDeleteMClientInfo",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x0D] = "R_DhcpEnumMScopeClients",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x0E] = "R_DhcpCreateOptionV5",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x0F] = "R_DhcpSetOptionInfoV5",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x10] = "R_DhcpGetOptionInfoV5",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x11] = "R_DhcpEnumOptionsV5",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x12] = "R_DhcpRemoveOptionV5",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x13] = "R_DhcpSetOptionValueV5",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x14] = "R_DhcpSetOptionValuesV5",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x15] = "R_DhcpGetOptionValueV5",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x16] = "R_DhcpEnumOptionValuesV5",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x17] = "R_DhcpRemoveOptionValueV5",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x18] = "R_DhcpCreateClass",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x19] = "R_DhcpModifyClass",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x1A] = "R_DhcpDeleteClass",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x1B] = "R_DhcpGetClassInfo",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x1C] = "R_DhcpEnumClasses",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x1D] = "R_DhcpGetAllOptions",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x1E] = "R_DhcpGetAllOptionValues",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x1F] = "R_DhcpGetMCastMibInfo",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x20] = "R_DhcpAuditLogSetParams",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x21] = "R_DhcpAuditLogGetParams",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x22] = "R_DhcpServerQueryAttribute",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x23] = "R_DhcpServerQueryAttributes",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x24] = "R_DhcpServerRedoAuthorization",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x25] = "R_DhcpAddSubnetElementV5",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x26] = "R_DhcpEnumSubnetElementsV5",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x27] = "R_DhcpRemoveSubnetElementV5",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x28] = "R_DhcpGetServerBindingInfo",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x29] = "R_DhcpSetServerBindingInfo",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x2A] = "R_DhcpQueryDnsRegCredentials",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x2B] = "R_DhcpSetDnsRegCredentials",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x2C] = "R_DhcpBackupDatabase",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x2D] = "R_DhcpRestoreDatabase",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x2E] = "R_DhcpGetServerSpecificStrings",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x2F] = "R_DhcpCreateOptionV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x30] = "R_DhcpSetOptionInfoV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x31] = "R_DhcpGetOptionInfoV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x32] = "R_DhcpEnumOptionsV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x33] = "R_DhcpRemoveOptionV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x34] = "R_DhcpSetOptionValueV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x35] = "R_DhcpEnumOptionValuesV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x36] = "R_DhcpRemoveOptionValueV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x37] = "R_DhcpGetAllOptionsV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x38] = "R_DhcpGetAllOptionValuesV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x39] = "R_DhcpCreateSubnetV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x3A] = "R_DhcpEnumSubnetsV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x3B] = "R_DhcpAddSubnetElementV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x3C] = "R_DhcpEnumSubnetElementsV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x3D] = "R_DhcpRemoveSubnetElementV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x3E] = "R_DhcpDeleteSubnetV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x3F] = "R_DhcpGetSubnetInfoV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x40] = "R_DhcpEnumSubnetClientsV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x41] = "R_DhcpServerSetConfigV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x42] = "R_DhcpServerGetConfigV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x43] = "R_DhcpGetMibInfoV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x45] = "R_DhcpGetServerBindingInfoV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x46] = "R_DhcpSetServerBindingInfoV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x47] = "R_DhcpSetClientInfoV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x48] = "R_DhcpGetClientInfoV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x49] = "R_DhcpDeleteClientInfoV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x4A] = "R_DhcpCreateClassV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x4B] = "R_DhcpModifyClassV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x4C] = "R_DhcpDeleteClassV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x4D] = "R_DhcpEnumClassesV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x4E] = "R_DhcpGetOptionValueV6",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x4F] = "R_DhcpSetSubnetDelayOffer",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x50] = "R_DhcpGetSubnetDelayOffer",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x51] = "R_DhcpGetMibInfoV5",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x52] = "R_DhcpAddFilterV4",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x53] = "R_DhcpDeleteFilterV4",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x54] = "R_DhcpSetFilterV4",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x55] = "R_DhcpGetFilterV4",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x56] = "R_DhcpEnumFilterV4",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x57] = "R_DhcpSetDnsRegCredentialsV5",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x58] = "R_DhcpEnumSubnetClientsFilterStatusInfo",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x59] = "R_DhcpV4FailoverCreateRelationship",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x5A] = "R_DhcpV4FailoverSetRelationship",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x5B] = "R_DhcpV4FailoverDeleteRelationship",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x5C] = "R_DhcpV4FailoverGetRelationship",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x5D] = "R_DhcpV4FailoverEnumRelationship",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x5E] = "R_DhcpV4FailoverAddScopeToRelationship",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x5F] = "R_DhcpV4FailoverDeleteScopeFromRelationship",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x60] = "R_DhcpV4FailoverGetScopeRelationship",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x61] = "R_DhcpV4FailoverGetScopeStatistics",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x62] = "R_DhcpV4FailoverGetClientInfo",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x63] = "R_DhcpV4FailoverGetSystemTime",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x64] = "R_DhcpV4FailoverTriggerAddrAllocation",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x65] = "R_DhcpV4SetOptionValue",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x66] = "R_DhcpV4SetOptionValues",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x67] = "R_DhcpV4GetOptionValue",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x68] = "R_DhcpV4RemoveOptionValue",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x69] = "R_DhcpV4GetAllOptionValues",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x6A] = "R_DhcpV4QueryPolicyEnforcement",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x6B] = "R_DhcpSetPolicyEnforcement",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x6C] = "R_DhcpV4CreatePolicy",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x6D] = "R_DhcpV4GetPolicy",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x6E] = "R_DhcpV4SetPolicy",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x6F] = "R_DhcpV4DeletePolicy",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x70] = "R_DhcpV4EnumPolicies",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x71] = "R_DhcpV4AddPolicyRange",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x72] = "R_DhcpV4RemovePolicyRange",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x73] = "R_DhcpV4EnumSubnetClients",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x74] = "R_DhcpV6SetStatelessStoreParams",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x75] = "R_DhcpV6GetStatelessStoreParams",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x76] = "R_DhcpV6GetStatelessStatistics",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x77] = "R_DhcpV4EnumSubnetReservations",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x78] = "R_DhcpV4GetFreeIPAddress",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x79] = "R_DhcpV6GetFreeIPAddress",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x7A] = "R_DhcpV4CreateClientInfo",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x7B] = "R_DhcpV4GetClientInfo",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x7C] = "R_DhcpV6CreateClientInfo",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x7D] = "R_DhcpV4FailoverGetAddressStatus",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x7E] = "R_DhcpV4CreatePolicyEx",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x7F] = "R_DhcpV4GetPolicyEx",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x80] = "R_DhcpV4SetPolicyEx",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x81] = "R_DhcpV4EnumPoliciesEx",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x82] = "R_DhcpV4EnumSubnetClientsEx",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x83] = "R_DhcpV4CreateClientInfoEx",
		["5b821720-f63b-11d0-aad2-00c04fc324db",0x84] = "R_DhcpV4GetClientInfoEx",

		# dsaop - MSDN Ref: Directory Replication Service (DRS) Remote Protocol [ms-drsr]
		["7c44d7d4-31d5-424c-bd5e-2b3e1f323d22",0x00] = "IDL_DSAPrepareScript",
		["7c44d7d4-31d5-424c-bd5e-2b3e1f323d22",0x01] = "IDL_DSAExecuteScript",

		# dscomm - MSDN Ref: Msg Queuing - Directory Service Protocol [ms-mqds]
		["77df7a80-f298-11d0-8358-00a024c480a8",0x00] = "S_DSCreateObject",
		["77df7a80-f298-11d0-8358-00a024c480a8",0x01] = "S_DSDeleteObject",
		["77df7a80-f298-11d0-8358-00a024c480a8",0x02] = "S_DSGetProps",
		["77df7a80-f298-11d0-8358-00a024c480a8",0x03] = "S_DSSetProps",
		["77df7a80-f298-11d0-8358-00a024c480a8",0x04] = "S_DSGetObjectSecurity",
		["77df7a80-f298-11d0-8358-00a024c480a8",0x05] = "S_DSSetObjectSecurity",
		["77df7a80-f298-11d0-8358-00a024c480a8",0x06] = "S_DSLookupBegin",
		["77df7a80-f298-11d0-8358-00a024c480a8",0x07] = "S_DSLookupNext",
		["77df7a80-f298-11d0-8358-00a024c480a8",0x08] = "S_DSLookupEnd",
		["77df7a80-f298-11d0-8358-00a024c480a8",0x09] = "Opnum9NotUsedOnWire",
		["77df7a80-f298-11d0-8358-00a024c480a8",0x0A] = "S_DSDeleteObjectGuid",
		["77df7a80-f298-11d0-8358-00a024c480a8",0x0B] = "S_DSGetPropsGuid",
		["77df7a80-f298-11d0-8358-00a024c480a8",0x0C] = "S_DSSetPropsGuid",
		["77df7a80-f298-11d0-8358-00a024c480a8",0x0D] = "S_DSGetObjectSecurityGuid",
		["77df7a80-f298-11d0-8358-00a024c480a8",0x0E] = "S_DSSetObjectSecurityGuid",
		["77df7a80-f298-11d0-8358-00a024c480a8",0x0F] = "Opnum15NotUsedOnWire",
		["77df7a80-f298-11d0-8358-00a024c480a8",0x10] = "Opnum16NotUsedOnWire",
		["77df7a80-f298-11d0-8358-00a024c480a8",0x11] = "Opnum17NotUsedOnWire",
		["77df7a80-f298-11d0-8358-00a024c480a8",0x12] = "Opnum18NotUsedOnWire",
		["77df7a80-f298-11d0-8358-00a024c480a8",0x13] = "S_DSQMSetMachineProperties",
		["77df7a80-f298-11d0-8358-00a024c480a8",0x14] = "S_DSCreateServersCache",
		["77df7a80-f298-11d0-8358-00a024c480a8",0x15] = "S_DSQMGetObjectSecurity",
		["77df7a80-f298-11d0-8358-00a024c480a8",0x16] = "S_DSValidateServer",
		["77df7a80-f298-11d0-8358-00a024c480a8",0x17] = "S_DSCloseServerHandle",
		["77df7a80-f298-11d0-8358-00a024c480a8",0x18] = "Opnum24NotUsedOnWire",
		["77df7a80-f298-11d0-8358-00a024c480a8",0x19] = "Opnum25NotUsedOnWire",
		["77df7a80-f298-11d0-8358-00a024c480a8",0x1A] = "Opnum26NotUsedOnWire",
		["77df7a80-f298-11d0-8358-00a024c480a8",0x1B] = "S_DSGetServerPort",

		# dscomm2 - MSDN Ref: Msg Queuing - Directory Service Protocol [ms-mqds]
		["708cca10-9569-11d1-b2a5-0060977d8118",0x00] = "S_DSGetComputerSites",
		["708cca10-9569-11d1-b2a5-0060977d8118",0x01] = "S_DSGetPropsEx",
		["708cca10-9569-11d1-b2a5-0060977d8118",0x02] = "S_DSGetPropsGuidEx",
		["708cca10-9569-11d1-b2a5-0060977d8118",0x03] = "S_DSBeginDeleteNotification",
		["708cca10-9569-11d1-b2a5-0060977d8118",0x04] = "S_DSNotifyDelete",
		["708cca10-9569-11d1-b2a5-0060977d8118",0x05] = "S_DSEndDeleteNotification",
		["708cca10-9569-11d1-b2a5-0060977d8118",0x06] = "S_DSIsServerGC",
		["708cca10-9569-11d1-b2a5-0060977d8118",0x07] = "Opnum7NotUsedOnWire",
		["708cca10-9569-11d1-b2a5-0060977d8118",0x08] = "S_DSGetGCListInDomain",

		# efsrpc - MSDN Ref: Encrypting File System Remote Protocol [ms-efsr]
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x00] = "EfsRpcOpenFileRaw",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x01] = "EfsRpcReadFileRaw",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x02] = "EfsRpcWriteFileRaw",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x03] = "EfsRpcCloseRaw",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x04] = "EfsRpcEncryptFileSrv",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x05] = "EfsDecryptFileSrv",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x06] = "EfsRpcQueryUsersOnFile",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x07] = "EfsRpcQueryRecoveryAgents",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x08] = "EfsRpcRemoveUsersFromFile",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x09] = "EfsRpcAddUsersToFile",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x0A] = "Opnum10NotUsedOnWire",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x0B] = "EfsRpcNotSupported",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x0C] = "EfsRpcFileKeyInfo",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x0D] = "EfsRpcDuplicateEncryptionInfoFile",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x0E] = "Opnum14NotUsedOnWire",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x0F] = "EfsRpcAddUsersToFileEx",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x10] = "EfsRpcFileKeyInfoEx",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x11] = "Opnum17NotUsedOnWire",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x12] = "EfsRpcGetEncryptedFileMetadata",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x13] = "EfsRpcSetEncryptedFileMetadata",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x14] = "EfsRpcFlushEfsCache",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x15] = "EfsRpcEncryptFileExServ",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x16] = "EfsRpcQueryProtectors",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x17] = "Opnum23NotUsedOnWire",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x18] = "Opnum24NotUsedOnWire",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x19] = "Opnum25NotUsedOnWire",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x1A] = "Opnum26NotUsedOnWire",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x1B] = "Opnum27NotUsedOnWire",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x1C] = "Opnum28NotUsedOnWire",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x1D] = "Opnum29NotUsedOnWire",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x1E] = "Opnum30NotUsedOnWire",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x1F] = "Opnum31NotUsedOnWire",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x20] = "Opnum32NotUsedOnWire",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x21] = "Opnum33NotUsedOnWire",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x22] = "Opnum34NotUsedOnWire",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x23] = "Opnum35NotUsedOnWire",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x24] = "Opnum36NotUsedOnWire",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x25] = "Opnum37NotUsedOnWire",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x26] = "Opnum38NotUsedOnWire",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x27] = "Opnum39NotUsedOnWire",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x28] = "Opnum40NotUsedOnWire",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x29] = "Opnum41NotUsedOnWire",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x2A] = "Opnum42NotUsedOnWire",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x2B] = "Opnum43NotUsedOnWire",
		["df1941c5-fe89-4e79-bf10-463657acf44d",0x2C] = "Opnum44NotUsedOnWire",

		# efsrpc2 - MSDN Ref: Encrypting File System Remote Protocol [ms-efsr]
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x00] = "EfsRpcOpenFileRaw",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x01] = "EfsRpcReadFileRaw",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x02] = "EfsRpcWriteFileRaw",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x03] = "EfsRpcCloseRaw",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x04] = "EfsRpcEncryptFileSrv",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x05] = "EfsDecryptFileSrv",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x06] = "EfsRpcQueryUsersOnFile",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x07] = "EfsRpcQueryRecoveryAgents",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x08] = "EfsRpcRemoveUsersFromFile",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x09] = "EfsRpcAddUsersToFile",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x0A] = "Opnum10NotUsedOnWire",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x0B] = "EfsRpcNotSupported",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x0C] = "EfsRpcFileKeyInfo",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x0D] = "EfsRpcDuplicateEncryptionInfoFile",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x0E] = "Opnum14NotUsedOnWire",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x0F] = "EfsRpcAddUsersToFileEx",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x10] = "EfsRpcFileKeyInfoEx",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x11] = "Opnum17NotUsedOnWire",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x12] = "EfsRpcGetEncryptedFileMetadata",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x13] = "EfsRpcSetEncryptedFileMetadata",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x14] = "EfsRpcFlushEfsCache",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x15] = "EfsRpcEncryptFileExServ",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x16] = "EfsRpcQueryProtectors",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x17] = "Opnum23NotUsedOnWire",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x18] = "Opnum24NotUsedOnWire",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x19] = "Opnum25NotUsedOnWire",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x1A] = "Opnum26NotUsedOnWire",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x1B] = "Opnum27NotUsedOnWire",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x1C] = "Opnum28NotUsedOnWire",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x1D] = "Opnum29NotUsedOnWire",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x1E] = "Opnum30NotUsedOnWire",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x1F] = "Opnum31NotUsedOnWire",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x20] = "Opnum32NotUsedOnWire",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x21] = "Opnum33NotUsedOnWire",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x22] = "Opnum34NotUsedOnWire",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x23] = "Opnum35NotUsedOnWire",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x24] = "Opnum36NotUsedOnWire",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x25] = "Opnum37NotUsedOnWire",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x26] = "Opnum38NotUsedOnWire",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x27] = "Opnum39NotUsedOnWire",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x28] = "Opnum40NotUsedOnWire",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x29] = "Opnum41NotUsedOnWire",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x2A] = "Opnum42NotUsedOnWire",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x2B] = "Opnum43NotUsedOnWire",
		["c681d488-d850-11d0-8c52-00c04fd90f7e",0x2C] = "Opnum44NotUsedOnWire",

		# FileServerVssAgent - MSDN Ref: File Server Remote VSS Protocol [ms-fsrvp]
		["a8e0653c-2744-4389-a61d-7373df8b2292",0x00] = "GetSupportedVersion",
		["a8e0653c-2744-4389-a61d-7373df8b2292",0x01] = "SetContext",
		["a8e0653c-2744-4389-a61d-7373df8b2292",0x02] = "StartShadowCopySet",
		["a8e0653c-2744-4389-a61d-7373df8b2292",0x03] = "AddToShadowCopySet",
		["a8e0653c-2744-4389-a61d-7373df8b2292",0x04] = "CommitShadowCopySet",
		["a8e0653c-2744-4389-a61d-7373df8b2292",0x05] = "ExposeShadowCopySet",
		["a8e0653c-2744-4389-a61d-7373df8b2292",0x06] = "RecoveryCompleteShadowCopySet",
		["a8e0653c-2744-4389-a61d-7373df8b2292",0x07] = "AbortShadowCopySet",
		["a8e0653c-2744-4389-a61d-7373df8b2292",0x08] = "IsPathSupported",
		["a8e0653c-2744-4389-a61d-7373df8b2292",0x09] = "IsPathShadowCopied",
		["a8e0653c-2744-4389-a61d-7373df8b2292",0x0A] = "GetShareMapping",
		["a8e0653c-2744-4389-a61d-7373df8b2292",0x0B] = "DeleteShareMapping",
		["a8e0653c-2744-4389-a61d-7373df8b2292",0x0C] = "PrepareShadowCopy",

		# FrsTransport - MSDN Ref: DFS Replication Protocol [ms-frs2]
		["897e2e5f-93f3-4376-9c9c-fd2277495c27",0x00] = "CheckConnectivity",
		["897e2e5f-93f3-4376-9c9c-fd2277495c27",0x01] = "EstablishConnection",
		["897e2e5f-93f3-4376-9c9c-fd2277495c27",0x02] = "EstablishSession",
		["897e2e5f-93f3-4376-9c9c-fd2277495c27",0x03] = "RequestUpdates",
		["897e2e5f-93f3-4376-9c9c-fd2277495c27",0x04] = "RequestVersionVector",
		["897e2e5f-93f3-4376-9c9c-fd2277495c27",0x05] = "AsyncPoll",
		["897e2e5f-93f3-4376-9c9c-fd2277495c27",0x06] = "RequestRecords",
		["897e2e5f-93f3-4376-9c9c-fd2277495c27",0x07] = "UpdateCancel",
		["897e2e5f-93f3-4376-9c9c-fd2277495c27",0x08] = "RawGetFileData",
		["897e2e5f-93f3-4376-9c9c-fd2277495c27",0x09] = "RdcGetSignatures",
		["897e2e5f-93f3-4376-9c9c-fd2277495c27",0x0A] = "RdcPushSourceNeeds",
		["897e2e5f-93f3-4376-9c9c-fd2277495c27",0x0B] = "RdcGetFileData",
		["897e2e5f-93f3-4376-9c9c-fd2277495c27",0x0C] = "RdcClose",
		["897e2e5f-93f3-4376-9c9c-fd2277495c27",0x0D] = "InitializeFileTransferAsync",
		["897e2e5f-93f3-4376-9c9c-fd2277495c27",0x0E] = "Opnum14NotUsedOnWire",
		["897e2e5f-93f3-4376-9c9c-fd2277495c27",0x0F] = "RawGetFileDataAsync",
		["897e2e5f-93f3-4376-9c9c-fd2277495c27",0x10] = "RdcGetFileDataAsync",
		["897e2e5f-93f3-4376-9c9c-fd2277495c27",0x11] = "RdcFileDataTransferKeepAlive",

		# IADProxy - MSDN Ref: DFS Replication Helper Protocol [ms-dfsrh]
		["4bb8ab1d-9ef9-4100-8eb6-dd4b4e418b72",0x03] = "CreateObject",
		["4bb8ab1d-9ef9-4100-8eb6-dd4b4e418b72",0x04] = "DeleteObject",
		["4bb8ab1d-9ef9-4100-8eb6-dd4b4e418b72",0x05] = "ModifyObject",

		# IADProxy2 - MSDN Ref: DFS Replication Helper Protocol [ms-dfsrh]
		["c4b0c7d9-abe0-4733-a1e1-9fdedf260c7a",0x06] = "CreateObject",
		["c4b0c7d9-abe0-4733-a1e1-9fdedf260c7a",0x07] = "DeleteObject",
		["c4b0c7d9-abe0-4733-a1e1-9fdedf260c7a",0x08] = "ModifyObject",

		# ICertAdminD - MSDN Ref: Certificate Services Remote Administration Protocol [ms-csra]
		["d99e6e71-fc88-11d0-b498-00a0c90312f3",0x03] = "SetExtension",
		["d99e6e71-fc88-11d0-b498-00a0c90312f3",0x04] = "SetAttributes",
		["d99e6e71-fc88-11d0-b498-00a0c90312f3",0x05] = "ResubmitRequest",
		["d99e6e71-fc88-11d0-b498-00a0c90312f3",0x06] = "DenyRequest",
		["d99e6e71-fc88-11d0-b498-00a0c90312f3",0x07] = "IsValidCertificate",
		["d99e6e71-fc88-11d0-b498-00a0c90312f3",0x08] = "PublishCRL",
		["d99e6e71-fc88-11d0-b498-00a0c90312f3",0x09] = "GetCRL",
		["d99e6e71-fc88-11d0-b498-00a0c90312f3",0x0A] = "RevokeCertificate",
		["d99e6e71-fc88-11d0-b498-00a0c90312f3",0x0B] = "EnumViewColumn",
		["d99e6e71-fc88-11d0-b498-00a0c90312f3",0x0C] = "GetViewDefaultColumnSet",
		["d99e6e71-fc88-11d0-b498-00a0c90312f3",0x0D] = "EnumAttributesOrExtensions",
		["d99e6e71-fc88-11d0-b498-00a0c90312f3",0x0E] = "OpenView",
		["d99e6e71-fc88-11d0-b498-00a0c90312f3",0x0F] = "EnumView",
		["d99e6e71-fc88-11d0-b498-00a0c90312f3",0x10] = "CloseView",
		["d99e6e71-fc88-11d0-b498-00a0c90312f3",0x11] = "ServerControl",
		["d99e6e71-fc88-11d0-b498-00a0c90312f3",0x12] = "Ping",
		["d99e6e71-fc88-11d0-b498-00a0c90312f3",0x13] = "GetServerState",
		["d99e6e71-fc88-11d0-b498-00a0c90312f3",0x14] = "BackupPrepare",
		["d99e6e71-fc88-11d0-b498-00a0c90312f3",0x15] = "BackupEnd",
		["d99e6e71-fc88-11d0-b498-00a0c90312f3",0x16] = "BackupGetAttachmentInformation",
		["d99e6e71-fc88-11d0-b498-00a0c90312f3",0x17] = "BackupGetBackupLogs",
		["d99e6e71-fc88-11d0-b498-00a0c90312f3",0x18] = "BackupOpenFile",
		["d99e6e71-fc88-11d0-b498-00a0c90312f3",0x19] = "BackupReadFile",
		["d99e6e71-fc88-11d0-b498-00a0c90312f3",0x1A] = "BackupCloseFile",
		["d99e6e71-fc88-11d0-b498-00a0c90312f3",0x1B] = "BackupTruncateLogs",
		["d99e6e71-fc88-11d0-b498-00a0c90312f3",0x1C] = "ImportCertificate",
		["d99e6e71-fc88-11d0-b498-00a0c90312f3",0x1D] = "BackupGetDynamicFiles",
		["d99e6e71-fc88-11d0-b498-00a0c90312f3",0x1E] = "RestoreGetDatabaseLocations",

		# ICertAdminD2 - MSDN Ref: Certificate Services Remote Administration Protocol [ms-csra]
		["7fe0d935-dda6-443f-85d0-1cfb58fe41dd",0x1F] = "PublishCRLs",
		["7fe0d935-dda6-443f-85d0-1cfb58fe41dd",0x20] = "GetCAProperty",
		["7fe0d935-dda6-443f-85d0-1cfb58fe41dd",0x21] = "SetCAProperty",
		["7fe0d935-dda6-443f-85d0-1cfb58fe41dd",0x22] = "GetCAPropertyInfo",
		["7fe0d935-dda6-443f-85d0-1cfb58fe41dd",0x23] = "EnumViewColumnTable",
		["7fe0d935-dda6-443f-85d0-1cfb58fe41dd",0x24] = "GetCASecurity",
		["7fe0d935-dda6-443f-85d0-1cfb58fe41dd",0x25] = "SetCASecurity",
		["7fe0d935-dda6-443f-85d0-1cfb58fe41dd",0x26] = "Ping2",
		["7fe0d935-dda6-443f-85d0-1cfb58fe41dd",0x27] = "GetArchivedKey",
		["7fe0d935-dda6-443f-85d0-1cfb58fe41dd",0x28] = "GetAuditFilter",
		["7fe0d935-dda6-443f-85d0-1cfb58fe41dd",0x29] = "SetAuditFilter",
		["7fe0d935-dda6-443f-85d0-1cfb58fe41dd",0x2A] = "GetOfficerRights",
		["7fe0d935-dda6-443f-85d0-1cfb58fe41dd",0x2B] = "SetOfficerRights",
		["7fe0d935-dda6-443f-85d0-1cfb58fe41dd",0x2C] = "GetConfigEntry",
		["7fe0d935-dda6-443f-85d0-1cfb58fe41dd",0x2D] = "SetConfigEntry",
		["7fe0d935-dda6-443f-85d0-1cfb58fe41dd",0x2E] = "ImportKey",
		["7fe0d935-dda6-443f-85d0-1cfb58fe41dd",0x2F] = "GetMyRoles",
		["7fe0d935-dda6-443f-85d0-1cfb58fe41dd",0x30] = "DeleteRow",

		# ICertRequestD - MSDN Ref: Windows Client Certificate Enrollment Protocol [ms-wcce]
		["d99e6e70-fc88-11d0-b498-00a0c90312f3",0x03] = "Request",
		["d99e6e70-fc88-11d0-b498-00a0c90312f3",0x04] = "GetCACert",
		["d99e6e70-fc88-11d0-b498-00a0c90312f3",0x05] = "Ping",

		# ICertRequestD2 - MSDN Ref: Windows Client Certificate Enrollment Protocol [ms-wcce]
		["5422fd3a-d4b8-4cef-a12e-e87d4ca22e90",0x03] = "Request",
		["5422fd3a-d4b8-4cef-a12e-e87d4ca22e90",0x04] = "GetCACert",
		["5422fd3a-d4b8-4cef-a12e-e87d4ca22e90",0x05] = "Ping",
		["5422fd3a-d4b8-4cef-a12e-e87d4ca22e90",0x06] = "Request2",
		["5422fd3a-d4b8-4cef-a12e-e87d4ca22e90",0x07] = "GetCAProperty",
		["5422fd3a-d4b8-4cef-a12e-e87d4ca22e90",0x08] = "GetCAPropertyInfo",
		["5422fd3a-d4b8-4cef-a12e-e87d4ca22e90",0x09] = "Ping2",

		# IDMNotify - MSDN Ref: Disk Mgmt Remote Protocol [ms-dmrp]
		["d2d79df7-3400-11d0-b40b-00aa005ff586",0x00] = "ObjectsChanged",

		# IDMRemoteServer - MSDN Ref: Disk Mgmt Remote Protocol [ms-dmrp]
		["3a410f21-553f-11d1-8e5e-00a0c92c9d5d",0x03] = "CreateRemoteObject",

		# IEnumWbemClassObject - MSDN Ref: WMI Remote Protocol [ms-wmi]
		["027947e1-d731-11ce-a357-000000000001",0x03] = "Reset",
		["027947e1-d731-11ce-a357-000000000001",0x04] = "Next",
		["027947e1-d731-11ce-a357-000000000001",0x05] = "NextAsync",
		["027947e1-d731-11ce-a357-000000000001",0x06] = "Clone",
		["027947e1-d731-11ce-a357-000000000001",0x07] = "Skip",

		# IEventService I Eventlog - MSDN Ref: Eventlog Remoting Protocol v6.0 [ms-even6]
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x00] = "EvtRpcRegisterRemoteSubscription",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x01] = "EvtRpcRemoteSubscriptionNextAsync",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x02] = "EvtRpcRemoteSubscriptionNext",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x03] = "EvtRpcRemoteSubscriptionWaitAsync",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x04] = "EvtRpcRegisterControllableOperation",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x05] = "EvtRpcRegisterLogQuery",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x06] = "EvtRpcClearLog",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x07] = "EvtRpcExportLog",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x08] = "EvtRpcLocalizeExportLog",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x09] = "EvtRpcMessageRender",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x0A] = "EvtRpcMessageRenderDefault",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x0B] = "EvtRpcQueryNext",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x0C] = "EvtRpcQuerySeek",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x0D] = "EvtRpcClose",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x0E] = "EvtRpcCancel",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x0F] = "EvtRpcAssertConfig",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x10] = "EvtRpcRetractConfig",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x11] = "EvtRpcOpenLogHandle",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x12] = "EvtRpcGetLogFileInfo",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x13] = "EvtRpcGetChannelList",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x14] = "EvtRpcGetChannelConfig",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x15] = "EvtRpcPutChannelConfig",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x16] = "EvtRpcGetPublisherList",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x17] = "EvtRpcGetPublisherListForChannel",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x18] = "EvtRpcGetPublisherMetadata",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x19] = "EvtRpcGetPublisherResourceMetadata",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x1A] = "EvtRpcGetEventMetadataEnum",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x1B] = "EvtRpcGetNextEventMetadata",
		["f6beaff7-1e19-4fbb-9f8f-b89e2018337c",0x1C] = "EvtRpcGetClassicLogDisplayName",

		# IIISApplicationAdmin - MSDN Ref: IIS IMSAdminBaseW Remote Protocol [ms-imsa]
		["7c4e1804-e342-483d-a43e-a850cfcc8d18",0x03] = "CreateApplication",
		["7c4e1804-e342-483d-a43e-a850cfcc8d18",0x04] = "DeleteApplication",
		["7c4e1804-e342-483d-a43e-a850cfcc8d18",0x05] = "CreateApplicationPool",
		["7c4e1804-e342-483d-a43e-a850cfcc8d18",0x06] = "DeleteApplicationPool",
		["7c4e1804-e342-483d-a43e-a850cfcc8d18",0x07] = "EnumerateApplicationsInPool",
		["7c4e1804-e342-483d-a43e-a850cfcc8d18",0x08] = "RecycleApplicationPool",
		["7c4e1804-e342-483d-a43e-a850cfcc8d18",0x09] = "GetProcessMode",

		# IIISCertObj - MSDN Ref: IIS IMSAdminBaseW Remote Protocol [ms-imsa]
		["bd0c73bc-805b-4043-9c30-9a28d64dd7d2",0x07] = "Opnum7NotUsedOnWire",
		["bd0c73bc-805b-4043-9c30-9a28d64dd7d2",0x08] = "Opnum8NotUsedOnWire",
		["bd0c73bc-805b-4043-9c30-9a28d64dd7d2",0x09] = "Opnum9NotUsedOnWire",
		["bd0c73bc-805b-4043-9c30-9a28d64dd7d2",0x0A] = "InstanceName",
		["bd0c73bc-805b-4043-9c30-9a28d64dd7d2",0x0B] = "Opnum11NotUsedOnWire",
		["bd0c73bc-805b-4043-9c30-9a28d64dd7d2",0x0C] = "IsInstallRemote",
		["bd0c73bc-805b-4043-9c30-9a28d64dd7d2",0x0D] = "Opnum13NotUsedOnWire",
		["bd0c73bc-805b-4043-9c30-9a28d64dd7d2",0x0E] = "IsExportableRemote",
		["bd0c73bc-805b-4043-9c30-9a28d64dd7d2",0x0F] = "Opnum15NotUsedOnWire",
		["bd0c73bc-805b-4043-9c30-9a28d64dd7d2",0x10] = "GetCertInfoRemote",
		["bd0c73bc-805b-4043-9c30-9a28d64dd7d2",0x11] = "Opnum17NotUsedOnWire",
		["bd0c73bc-805b-4043-9c30-9a28d64dd7d2",0x12] = "Opnum18NotUsedOnWire",
		["bd0c73bc-805b-4043-9c30-9a28d64dd7d2",0x13] = "Opnum19NotUsedOnWire",
		["bd0c73bc-805b-4043-9c30-9a28d64dd7d2",0x14] = "Opnum20NotUsedOnWire",
		["bd0c73bc-805b-4043-9c30-9a28d64dd7d2",0x15] = "Opnum21NotUsedOnWire",
		["bd0c73bc-805b-4043-9c30-9a28d64dd7d2",0x16] = "ImportFromBlob",
		["bd0c73bc-805b-4043-9c30-9a28d64dd7d2",0x17] = "ImportFromBlobGetHash",
		["bd0c73bc-805b-4043-9c30-9a28d64dd7d2",0x18] = "Opnum24NotUsedOnWire",
		["bd0c73bc-805b-4043-9c30-9a28d64dd7d2",0x19] = "ExportToBlob",

		# IIisServiceControl - MSDN Ref: IIS Service Control Protocol [ms-iiss]
		["e8fb8620-588f-11d2-9d61-00c04f79c5fe",0x07] = "Stop",
		["e8fb8620-588f-11d2-9d61-00c04f79c5fe",0x08] = "Start",
		["e8fb8620-588f-11d2-9d61-00c04f79c5fe",0x09] = "Reboot",
		["e8fb8620-588f-11d2-9d61-00c04f79c5fe",0x0A] = "Status",
		["e8fb8620-588f-11d2-9d61-00c04f79c5fe",0x0B] = "Kill",

		# IManagedObject - MSDN Ref: IManagedObject Interface Protocol [ms-ioi]
		["c3fcc19e-a970-11d2-8b5a-00a0c9b7c9c4",0x03] = "GetSerializedBuffer",
		["c3fcc19e-a970-11d2-8b5a-00a0c9b7c9c4",0x04] = "GetObjectIdentify",

		# IManageTelnetSessions - MSDN Ref: Telnet Server Remote Administration Protocol [ms-tsrap]
		["034634fd-ba3f-11d1-856a-00a0c944138c",0x07] = "GetTelnetSessions",
		["034634fd-ba3f-11d1-856a-00a0c944138c",0x08] = "TerminateSession",
		["034634fd-ba3f-11d1-856a-00a0c944138c",0x09] = "SendMsgToASession",

		# IMSAdminBase2W - MSDN Ref: IIS IMSAdminBaseW Remote Protocol [ms-imsa]
		["8298d101-f992-43b7-8eca-5052d885b995",0x22] = "BackupWithPasswrd",
		["8298d101-f992-43b7-8eca-5052d885b995",0x23] = "RestoreWithPasswrd",
		["8298d101-f992-43b7-8eca-5052d885b995",0x24] = "Export",
		["8298d101-f992-43b7-8eca-5052d885b995",0x25] = "Import",
		["8298d101-f992-43b7-8eca-5052d885b995",0x26] = "RestoreHistory",
		["8298d101-f992-43b7-8eca-5052d885b995",0x27] = "EnumHistory",

		# IMSAdminBase3W - MSDN Ref: IIS IMSAdminBaseW Remote Protocol [ms-imsa]
		["f612954d-3b0b-4c56-9563-227b7be624b4",0x28] = "GetChildPaths",

		# IMSAdminBaseW - MSDN Ref: IIS IMSAdminBaseW Remote Protocol [ms-imsa]
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x03] = "AddKey",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x04] = "DeleteKey",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x05] = "DeleteChildKEys",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x06] = "EnumKeys",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x07] = "CopyKey",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x08] = "RenameKey",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x09] = "R_SetData",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x0A] = "R_GetData",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x0B] = "DeleteDate",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x0C] = "R_EnumData",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x0D] = "R_GetAllData",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x0E] = "DeleteAllData",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x0F] = "CopyData",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x10] = "GetDataPaths",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x11] = "OpenKey",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x12] = "CloseKey",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x13] = "ChangePermissions",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x14] = "SaveData",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x15] = "GetHandleInfo",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x16] = "GetSystemChangeNumber",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x17] = "GetDataSetNumber",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x18] = "SetLastChangeTime",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x19] = "GetLastChangeTime",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x1A] = "R_KeyExchangePhase1",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x1B] = "R_KeyExchangePhase2",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x1C] = "Backup",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x1D] = "Restore",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x1E] = "EnumBackups",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x1F] = "DeleteBackup",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x20] = "UnmarshalInterface",
		["70b51430-b6ca-11d0-b9b9-00a0c922e750",0x21] = "R_GetServerGuid",

		# inetinfo - MSDN Ref: IIS Inetinfo Remote Protocol [ms-irp]
		["82ad4280-036b-11cf-972c-00aa006887b0",0x00] = "R_InetInfoGetVersion",
		["82ad4280-036b-11cf-972c-00aa006887b0",0x01] = "R_InetInfoGetAdminInformation",
		["82ad4280-036b-11cf-972c-00aa006887b0",0x02] = "R_InsetInfoGetSites",
		["82ad4280-036b-11cf-972c-00aa006887b0",0x03] = "R_InetInfoSetAdminInformation",
		["82ad4280-036b-11cf-972c-00aa006887b0",0x04] = "R_InetInfoGetGlobalAdminInformation",
		["82ad4280-036b-11cf-972c-00aa006887b0",0x05] = "R_InetInfoSetGlobalAdminInformation",
		["82ad4280-036b-11cf-972c-00aa006887b0",0x06] = "R_InetInfoQueryStatistics",
		["82ad4280-036b-11cf-972c-00aa006887b0",0x07] = "R_InetInfoClearStatistics",
		["82ad4280-036b-11cf-972c-00aa006887b0",0x08] = "R_InetInfoFlushMemoryCache",
		["82ad4280-036b-11cf-972c-00aa006887b0",0x09] = "R_InetInfoGetServerCapabilities",
		["82ad4280-036b-11cf-972c-00aa006887b0",0x0A] = "R_W3QueryStatistics2",
		["82ad4280-036b-11cf-972c-00aa006887b0",0x0B] = "R_W3ClearStatistics2",
		["82ad4280-036b-11cf-972c-00aa006887b0",0x0C] = "R_FtpQueryStatistics2",
		["82ad4280-036b-11cf-972c-00aa006887b0",0x0D] = "R_FtpClearStatistics2",
		["82ad4280-036b-11cf-972c-00aa006887b0",0x0E] = "R_IISDEnumerateUsers",
		["82ad4280-036b-11cf-972c-00aa006887b0",0x0F] = "R_IISDisconnectedUser",
		["82ad4280-036b-11cf-972c-00aa006887b0",0x10] = "Opnum16NotUsedOnWire",
		["82ad4280-036b-11cf-972c-00aa006887b0",0x11] = "Opnum17NotUsedOnWire",

		# IRemoteDispatch - MSDN Ref: IManagedObject Interface Protocol [ms-ioi]
		["6619a740-8154-43be-a186-0319578e02db",0x07] = "RemoteDispatchAutoDone",
		["6619a740-8154-43be-a186-0319578e02db",0x08] = "RemoteDispatchNotAutoDone",

		# IRemUnknown - MSDN Ref: DCOM Remote Protocol [ms-dcom]
		["00000131-0000-0000-c000-000000000046",0x03] = "RemQueryInterface",
		["00000131-0000-0000-c000-000000000046",0x04] = "RemAddRef",
		["00000131-0000-0000-c000-000000000046",0x05] = "RemRelease",

		# IResourceManager - MSDN Ref: Windows System Resource Manager Protocol [ms-wsrm]
		["c5cebee2-9df5-4cdd-a08c-c2471bc144b4",0x07] = "RetrieveEventList",
		["c5cebee2-9df5-4cdd-a08c-c2471bc144b4",0x08] = "GetSystemAffinity",
		["c5cebee2-9df5-4cdd-a08c-c2471bc144b4",0x09] = "ImportXMLFiles",
		["c5cebee2-9df5-4cdd-a08c-c2471bc144b4",0x0A] = "ExportXMLFiles",
		["c5cebee2-9df5-4cdd-a08c-c2471bc144b4",0x0B] = "RestoreXMLFiles",
		["c5cebee2-9df5-4cdd-a08c-c2471bc144b4",0x0C] = "GetDependencies",
		["c5cebee2-9df5-4cdd-a08c-c2471bc144b4",0x0D] = "GetServiceList",
		["c5cebee2-9df5-4cdd-a08c-c2471bc144b4",0x0E] = "GetllSAppPoolNames",
		["c5cebee2-9df5-4cdd-a08c-c2471bc144b4",0x0F] = "GetServerName",
		["c5cebee2-9df5-4cdd-a08c-c2471bc144b4",0x10] = "GetCurrentMemory",

		# IResourceManager2 - MSDN Ref: Windows System Resource Manager Protocol [ms-wsrm]
		["2a3eb639-d134-422d-90d8-aaa1b5216202",0x07] = "ExportObjects",
		["2a3eb639-d134-422d-90d8-aaa1b5216202",0x08] = "GetImportConflicts",
		["2a3eb639-d134-422d-90d8-aaa1b5216202",0x09] = "ImportXml",
		["2a3eb639-d134-422d-90d8-aaa1b5216202",0x0A] = "ExportXml",

		# ISDKey - MSDN Ref: Group Key Distribution Protocol [ms-gkdi]
		["b9785960-524f-11df-8b6d-83dcded72085",0x00] = "GetKey",

		# IServerHealthReport - MSDN Ref: DFS Replication Helper Protocol [ms-dfsrh]
		["e65e8028-83e8-491b-9af7-aaf6bd51a0ce",0x03] = "GetReport",
		["e65e8028-83e8-491b-9af7-aaf6bd51a0ce",0x04] = "GetCompressedReport",
		["e65e8028-83e8-491b-9af7-aaf6bd51a0ce",0x05] = "GetRawReportEx",
		["e65e8028-83e8-491b-9af7-aaf6bd51a0ce",0x06] = "GetReferenceVersionVectors",
		["e65e8028-83e8-491b-9af7-aaf6bd51a0ce",0x07] = "Opnum7NotUsedOnWire",
		["e65e8028-83e8-491b-9af7-aaf6bd51a0ce",0x08] = "GetReferenceBacklogCounts",

		# IServerHealthReport2 - MSDN Ref: DFS Replication Helper Protocol [ms-dfsrh]
		["20d15747-6c48-4254-a358-65039fd8c63c",0x09] = "GetReport",
		["20d15747-6c48-4254-a358-65039fd8c63c",0x10] = "GetCompressedReport",

		# IServicedComponentInfo - MSDN Ref: IManagedObject Interface Protocol [ms-ioi]
		["8165b19e-8d3a-4d0b-80c8-97de310db583",0x03] = "GetComponentInfo",

		# ITpmVirtualSmartCardManager - MSDN Ref: TPM Virtual Smart Card Mgmt Protocol [ms-tpmvsc]
		["112b1dff-d9dc-41f7-869f-d67fee7cb591",0x03] = "CreateVirtualSmartCard",
		["112b1dff-d9dc-41f7-869f-d67fee7cb591",0x04] = "DestroyVirtualSmartCard",

		# ITpmVirtualSmartCardManager2 - MSDN Ref: TPM Virtual Smart Card Mgmt Protocol [ms-tpmvsc]
		["fdf8a2b9-02de-47f4-bc26-aa85ab5e5267",0x05] = "CreateVirtualSmartCardWithPinPolicy",

		# ITpmVirtualSmartCardManager3 - MSDN Ref: TPM Virtual Smart Card Mgmt Protocol [ms-tpmvsc]
		["3c745a97-f375-4150-be17-5950f694c699",0x06] = "CreateVirtualSmartCardWithAttestation",

		# ITpmVirtualSmartCardManagerStatusCallback - MSDN Ref: TPM Virtual Smart Card Mgmt Protocol [ms-tpmvsc]
		["1a1bb35f-abb8-451c-a1ae-33d98f1bef4a",0x03] = "ReportProgress",
		["1a1bb35f-abb8-451c-a1ae-33d98f1bef4a",0x04] = "ReportError",

		# IUnknown - MSDN Ref: DCOM Remote Protocol [ms-dcom]
		["00000000-0000-0000-c000-000000000046",0x00] = "Opnum0NotUsedOnWire",
		["00000000-0000-0000-c000-000000000046",0x01] = "Opnum1NotUsedOnWire",
		["00000000-0000-0000-c000-000000000046",0x02] = "Opnum2NotUsedOnWire",

		# IVolumeClient - MSDN Ref: Disk Mgmt Remote Protocol [ms-dmrp]
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x03] = "EnumDisksEx",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x04] = "EnumDiskRegionsEx",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x05] = "CreatePartition",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x06] = "CreatePartitionAssignAndFormat",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x07] = "CreatePartitionAssignandFormatEx",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x08] = "DeletePartition",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x09] = "WriteSignature",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x0A] = "MarkActivePartition",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x0B] = "Eject",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x0C] = "Opnum12NotUsedOnWire",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x0D] = "FTEnumVolumes",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x0E] = "FTEnumLogicalDiskMembers",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x0F] = "FTDeleteVolume",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x10] = "FTBreakMirror",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x11] = "FTResyncMirror",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x12] = "FTRegenerateParityStripe",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x13] = "FTReplaceMirrorPartition",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x14] = "FTReplaceParityStripePartition",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x15] = "EnumDriveLetters",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x16] = "AssignDriveLetter",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x17] = "FreeDriveLetter",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x18] = "EnumLocalFileSystems",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x19] = "GetInstalledFileSystems",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x1A] = "Format",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x1B] = "Opnum27NotUsedOnWire",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x1C] = "EnumVolumes",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x1D] = "EnumVolumeMembers",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x1E] = "CreateVolume",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x1F] = "CreateVolumeAssignAndFormat",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x20] = "CreateVolumeAssignAndFormatEx",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x21] = "GetVolumeMountName",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x22] = "GrowVolume",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x23] = "DeleteVolume",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x24] = "AddMirror",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x25] = "RemoveMirror",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x26] = "SplitMirror",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x27] = "InitializeDiskEx",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x28] = "UninitializeDisk",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x29] = "ReConnectDisk",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x2A] = "Opnum42NotUsedOnWire",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x2B] = "ImportDiskGroup",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x2C] = "DiskMergeQuery",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x2D] = "DiskMerge",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x2E] = "Opnum46NotUsedOnWire",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x2F] = "ReAttachDisk",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x30] = "Opnum48NotUsedOnWire",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x31] = "Opnum49NotUsedOnWire",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x32] = "Opnum50NotUsedOnWire",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x33] = "ReplaceRaid5Column",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x34] = "RestartVolume",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x35] = "GetEncapsulateDiskInfoEx",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x36] = "EncapsulateDiskEx",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x37] = "QueryChangePartitionNumbers",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x38] = "DeletePartitionNumberInfoFromRegistry",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x39] = "SetDontShow",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x3A] = "GetDontShow",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x3B] = "Opnum59NotUsedOnWire",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x3C] = "Opnum60NotUsedOnWire",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x3D] = "Opnum61NotUsedOnWire",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x3E] = "Opnum62NotUsedOnWire",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x3F] = "Opnum63NotUsedOnWire",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x40] = "Opnum64NotUsedOnWire",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x41] = "Opnum65NotUsedOnWire",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x42] = "Opnum66NotUsedOnWire",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x43] = "EnumTasks",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x44] = "GetTaskDetail",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x45] = "AbortTask",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x46] = "HrGetErrorData",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x47] = "Initialize",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x48] = "Uninitialize",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x49] = "Refresh",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x4A] = "RescanDisks",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x4B] = "RefreshFileSys",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x4C] = "SecureSystemPartition",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x4D] = "ShutDownSystem",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x4E] = "EnumAccessPath",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x4F] = "EnumAccessPathForVolume",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x50] = "AddAccessPath",
		["d2d79df5-3400-11d0-b40b-00aa005ff586",0x51] = "DeleteAccessPath",

		# IVolumeClient2 - MSDN Ref: Disk Mgmt Remote Protocol [ms-dmrp]
		["4bdafc52-fe6a-11d2-93f8-00105a11164a",0x03] = "GetMaxAdjustedFreeSpace",

		# IVolumeClient3 - MSDN Ref: Disk Mgmt Remote Protocol [ms-dmrp]
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x03] = "EnumDisksEx",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x04] = "EnumDiskRegionsEx",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x05] = "CreatePartition",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x06] = "CreatePartitionAssignAndFormat",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x07] = "CreatePartitionAssignandFormatEx",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x08] = "DeletePartition",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x09] = "InitializeDiskStyle",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x0A] = "MarkActivePartition",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x0B] = "Eject",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x0C] = "Opnum12NotUsedOnWire",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x0D] = "FTEnumVolumes",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x0E] = "FTEnumLogicalDiskMembers",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x0F] = "FTDeleteVolume",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x10] = "FTBreakMirror",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x11] = "FTResyncMirror",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x12] = "FTRegenerateParityStripe",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x13] = "FTReplaceMirrorPartition",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x14] = "FTReplaceParityStripePartition",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x15] = "EnumDriveLetters",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x16] = "AssignDriveLetter",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x17] = "FreeDriveLetter",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x18] = "EnumLocalFileSystems",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x19] = "GetInstalledFileSystems",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x1A] = "Format",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x1B] = "EnumVolumes",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x1C] = "EnumVolumeMembers",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x1D] = "CreateVolume",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x1E] = "CreateVolumeAssignAndFormat",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x1F] = "CreateVolumeAssignAndFormatEx",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x20] = "GetVolumeMountName",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x21] = "GrowVolume",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x22] = "DeleteVolume",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x23] = "CreatePartitionsForVolume",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x24] = "DeletePartitionsForVolume",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x25] = "GetMaxAdjustedFreeSpace",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x26] = "AddMirror",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x27] = "RemoveMirror",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x28] = "SplitMirror",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x29] = "InitializeDiskEx",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x2A] = "UninitializeDisk",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x2B] = "ReConnectDisk",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x2C] = "ImportDiskGroup",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x2D] = "DiskMergeQuery",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x2E] = "DiskMerge",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x2F] = "ReAttachDisk",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x30] = "ReplaceRaid5Column",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x31] = "RestartVolume",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x32] = "GetEncapsulateDiskInfoEx",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x33] = "EncapsulateDiskEx",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x34] = "QueryChangePartitionNumbers",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x35] = "DeletePartitionNumberInfoFromRegistry",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x36] = "SetDontShow",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x37] = "GetDontShow",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x38] = "Opnum56NotUsedOnWire",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x39] = "Opnum57NotUsedOnWire",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x3A] = "Opnum58NotUsedOnWire",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x3B] = "Opnum59NotUsedOnWire",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x3C] = "Opnum60NotUsedOnWire",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x3D] = "Opnum61NotUsedOnWire",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x3E] = "Opnum62NotUsedOnWire",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x3F] = "Opnum63NotUsedOnWire",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x40] = "EnumTasks",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x41] = "GetTaskDetail",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x42] = "AbortTask",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x43] = "HrGetErrorData",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x44] = "Initialize",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x45] = "Uninitialize",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x46] = "Refresh",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x47] = "RescanDisks",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x48] = "RefreshFileSys",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x49] = "SecureSystemPartition",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x4A] = "ShutDownSystem",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x4B] = "EnumAccessPath",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x4C] = "EnumAccessPathForVolume",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x4D] = "AddAccessPath",
		["135698d2-3a37-4d26-99df-e2bb6ae3ac61",0x4E] = "DeleteAccessPath",

		# IVolumeClient4 - MSDN Ref: Disk Mgmt Remote Protocol [ms-dmrp]
		["deb01010-3a37-4d26-99df-e2bb6ae3ac61",0x03] = "RefreshEx",
		["deb01010-3a37-4d26-99df-e2bb6ae3ac61",0x04] = "GetVolumeDeviceName",

		# IVssDifferentialSoftwareSnapshotMgmt - MSDN Ref: Shadow Copy Mgmt Protocol [ms-scmp]
		["214a0f28-b737-4026-b847-4f9e37d79529",0x03] = "AddDiffArea",
		["214a0f28-b737-4026-b847-4f9e37d79529",0x04] = "ChangeDiffAreaMaximizeSize",
		["214a0f28-b737-4026-b847-4f9e37d79529",0x05] = "QueryVolumesSupportedForDiffAreas",
		["214a0f28-b737-4026-b847-4f9e37d79529",0x06] = "QueryDiffAreasForVolume",
		["214a0f28-b737-4026-b847-4f9e37d79529",0x07] = "QueryDiffAreaOnVolume",
		["214a0f28-b737-4026-b847-4f9e37d79529",0x08] = "Opnum08NotUsedOnWire",

		# IVssEnumMgmtObject - MSDN Ref: Shadow Copy Mgmt Protocol [ms-scmp]
		["01954e6b-9254-4e6e-808c-c9e05d007696",0x03] = "Next",
		["01954e6b-9254-4e6e-808c-c9e05d007696",0x04] = "Skip",
		["01954e6b-9254-4e6e-808c-c9e05d007696",0x05] = "Reset",
		["01954e6b-9254-4e6e-808c-c9e05d007696",0x06] = "Clone",

		# IVssEnumObject - MSDN Ref: Shadow Copy Mgmt Protocol [ms-scmp]
		["ae1c7110-2f60-11d3-8a39-00c04f72d8e3",0x03] = "Next",
		["ae1c7110-2f60-11d3-8a39-00c04f72d8e3",0x04] = "Skip",
		["ae1c7110-2f60-11d3-8a39-00c04f72d8e3",0x05] = "Reset",
		["ae1c7110-2f60-11d3-8a39-00c04f72d8e3",0x06] = "Clone",

		# IVssSnapshotMgmt - MSDN Ref: Shadow Copy Mgmt Protocol [ms-scmp]
		["fa7df749-66e7-4986-a27f-e2f04ae53772",0x03] = "GetProviderMgmtInterface",
		["fa7df749-66e7-4986-a27f-e2f04ae53772",0x04] = "QueryVolumesSupportedForSnapshots",
		["fa7df749-66e7-4986-a27f-e2f04ae53772",0x05] = "QuerySnapshotsByVolume",

		# IWamAdmin - MSDN Ref: IIS IMSAdminBaseW Remote Protocol [ms-imsa]
		["29822ab7-f302-11d0-9953-00c04fd919c1",0x03] = "AppCreate",
		["29822ab7-f302-11d0-9953-00c04fd919c1",0x04] = "AppDelete",
		["29822ab7-f302-11d0-9953-00c04fd919c1",0x05] = "AppUnLoad",
		["29822ab7-f302-11d0-9953-00c04fd919c1",0x06] = "AppGetStatus",
		["29822ab7-f302-11d0-9953-00c04fd919c1",0x07] = "AppDeleteRecoverable",
		["29822ab7-f302-11d0-9953-00c04fd919c1",0x08] = "AppRecover",

		# IWamAdmin2 - MSDN Ref: IIS IMSAdminBaseW Remote Protocol [ms-imsa]
		["29822ab8-f302-11d0-9953-00c04fd919c1",0x09] = "AppCreate2",

		# IWRMAccounting - MSDN Ref: Windows System Resource Manager Protocol [ms-wsrm]
		["4f7ca01c-a9e5-45b6-b142-2332a1339c1d",0x07] = "CreateAccountingDb",
		["4f7ca01c-a9e5-45b6-b142-2332a1339c1d",0x08] = "GetAccountingMetadata",
		["4f7ca01c-a9e5-45b6-b142-2332a1339c1d",0x09] = "ExecuteAccountingQuery",
		["4f7ca01c-a9e5-45b6-b142-2332a1339c1d",0x0A] = "GetRawAccountingData",
		["4f7ca01c-a9e5-45b6-b142-2332a1339c1d",0x0B] = "GetNextAccountingDataBatch",
		["4f7ca01c-a9e5-45b6-b142-2332a1339c1d",0x0C] = "DeleteAccountingData",
		["4f7ca01c-a9e5-45b6-b142-2332a1339c1d",0x0D] = "DefragmentDB",
		["4f7ca01c-a9e5-45b6-b142-2332a1339c1d",0x0E] = "CancelAccountingQuery",
		["4f7ca01c-a9e5-45b6-b142-2332a1339c1d",0x0F] = "RegisterAccountingClient",
		["4f7ca01c-a9e5-45b6-b142-2332a1339c1d",0x10] = "DumpAccountingData",
		["4f7ca01c-a9e5-45b6-b142-2332a1339c1d",0x11] = "GetAccountingClients",
		["4f7ca01c-a9e5-45b6-b142-2332a1339c1d",0x12] = "SetAccountingClientStatus",
		["4f7ca01c-a9e5-45b6-b142-2332a1339c1d",0x13] = "CheckAccountingConnection",
		["4f7ca01c-a9e5-45b6-b142-2332a1339c1d",0x14] = "SetClientPermissions",

		# IWRMCalendar - MSDN Ref: Windows System Resource Manager Protocol [ms-wsrm]
		["481e06cf-ab04-4498-8ffe-124a0a34296d",0x07] = "GetCalendarInfo",
		["481e06cf-ab04-4498-8ffe-124a0a34296d",0x08] = "CreateCalendar",
		["481e06cf-ab04-4498-8ffe-124a0a34296d",0x09] = "ModifyCalendar",
		["481e06cf-ab04-4498-8ffe-124a0a34296d",0x0A] = "DeleteCalendar",
		["481e06cf-ab04-4498-8ffe-124a0a34296d",0x0B] = "RenameCalendar",
		["481e06cf-ab04-4498-8ffe-124a0a34296d",0x0C] = "ComputeEvents",
		["481e06cf-ab04-4498-8ffe-124a0a34296d",0x0D] = "GetScheduleInfo",
		["481e06cf-ab04-4498-8ffe-124a0a34296d",0x0E] = "CreateSchedule",
		["481e06cf-ab04-4498-8ffe-124a0a34296d",0x0F] = "ModifySchedule",
		["481e06cf-ab04-4498-8ffe-124a0a34296d",0x10] = "DeleteSchedule",
		["481e06cf-ab04-4498-8ffe-124a0a34296d",0x11] = "RenameSchedule",
		["481e06cf-ab04-4498-8ffe-124a0a34296d",0x12] = "MoveBeforeCalendar",
		["481e06cf-ab04-4498-8ffe-124a0a34296d",0x13] = "MoveAfterCalendar",
		["481e06cf-ab04-4498-8ffe-124a0a34296d",0x14] = "GetServerTimeZone",

		# IWRMConfig - MSDN Ref: Windows System Resource Manager Protocol [ms-wsrm]
		["21546ae8-4da5-445e-987f-627fea39c5e8",0x07] = "GetConfig",
		["21546ae8-4da5-445e-987f-627fea39c5e8",0x08] = "SetConfig",
		["21546ae8-4da5-445e-987f-627fea39c5e8",0x09] = "IsEnabled",
		["21546ae8-4da5-445e-987f-627fea39c5e8",0x0A] = "EnableDisable",
		["21546ae8-4da5-445e-987f-627fea39c5e8",0x0B] = "GetExclusionList",
		["21546ae8-4da5-445e-987f-627fea39c5e8",0x0C] = "SetExclusionList",
		["21546ae8-4da5-445e-987f-627fea39c5e8",0x0D] = "WSRMActivate",
		["21546ae8-4da5-445e-987f-627fea39c5e8",0x0E] = "IsWSRMActivated",
		["21546ae8-4da5-445e-987f-627fea39c5e8",0x0F] = "RestoreExclusionList",

		# IWRMMachineGroup - MSDN Ref: Windows System Resource Manager Protocol [ms-wsrm]
		["943991a5-b3fe-41fa-9696-7f7b656ee34b",0x07] = "CreateMachineGroup",
		["943991a5-b3fe-41fa-9696-7f7b656ee34b",0x08] = "GetMachineGroupInfo",
		["943991a5-b3fe-41fa-9696-7f7b656ee34b",0x09] = "ModifyMachineGroup",
		["943991a5-b3fe-41fa-9696-7f7b656ee34b",0x0A] = "DeleteMachineGroup",
		["943991a5-b3fe-41fa-9696-7f7b656ee34b",0x0B] = "RenameMachineGroup",
		["943991a5-b3fe-41fa-9696-7f7b656ee34b",0x0C] = "AddMachine",
		["943991a5-b3fe-41fa-9696-7f7b656ee34b",0x0D] = "GetMachineInfo",
		["943991a5-b3fe-41fa-9696-7f7b656ee34b",0x0E] = "ModifyMachineInfo",
		["943991a5-b3fe-41fa-9696-7f7b656ee34b",0x0F] = "DeleteMachine",

		# IWRMPolicy - MSDN Ref: Windows System Resource Manager Protocol [ms-wsrm]
		["59602eb6-57b0-4fd8-aa4b-ebf06971fe15",0x07] = "GetPolicyInfo",
		["59602eb6-57b0-4fd8-aa4b-ebf06971fe15",0x08] = "CreatePolicy",
		["59602eb6-57b0-4fd8-aa4b-ebf06971fe15",0x09] = "ModifyPolicy",
		["59602eb6-57b0-4fd8-aa4b-ebf06971fe15",0x0A] = "DeletePolicy",
		["59602eb6-57b0-4fd8-aa4b-ebf06971fe15",0x0B] = "RenameAllocationPolicy",
		["59602eb6-57b0-4fd8-aa4b-ebf06971fe15",0x0C] = "MoveBefore",
		["59602eb6-57b0-4fd8-aa4b-ebf06971fe15",0x0D] = "MoveAfter",
		["59602eb6-57b0-4fd8-aa4b-ebf06971fe15",0x0E] = "SetCalDefaultPolicyName",
		["59602eb6-57b0-4fd8-aa4b-ebf06971fe15",0x0F] = "GetCalDefaultPolicyName",
		["59602eb6-57b0-4fd8-aa4b-ebf06971fe15",0x10] = "GetProcessList",
		["59602eb6-57b0-4fd8-aa4b-ebf06971fe15",0x11] = "GetCurrentPolicy",
		["59602eb6-57b0-4fd8-aa4b-ebf06971fe15",0x12] = "SetCurrentPolicy",
		["59602eb6-57b0-4fd8-aa4b-ebf06971fe15",0x13] = "GetCurrentStateAndActivePolicyName",
		["59602eb6-57b0-4fd8-aa4b-ebf06971fe15",0x14] = "GetConditionalPolicy",
		["59602eb6-57b0-4fd8-aa4b-ebf06971fe15",0x15] = "SetConditionalPolicy",

		# IWRMProtocol - MSDN Ref: Windows System Resource Manager Protocol [ms-wsrm]
		["f31931a9-832d-481c-9503-887a0e6a79f0",0x07] = "GetSupportedClient",

		# IWRMRemoteSessionMgmt - MSDN Ref: Windows System Resource Manager Protocol [ms-wsrm]
		["fc910418-55ca-45ef-b264-83d4ce7d30e0",0x07] = "GetRemoteUserCategories",
		["fc910418-55ca-45ef-b264-83d4ce7d30e0",0x08] = "SetRemoteUserCategories",
		["fc910418-55ca-45ef-b264-83d4ce7d30e0",0x09] = "RefreshRemoteSessionWeights",

		# IWRMResourceGroup - MSDN Ref: Windows System Resource Manager Protocol [ms-wsrm]
		["bc681469-9dd9-4bf4-9b3d-709f69efe431",0x07] = "GetResourceGroupInfo",
		["bc681469-9dd9-4bf4-9b3d-709f69efe431",0x08] = "ModifyResourceGroup",
		["bc681469-9dd9-4bf4-9b3d-709f69efe431",0x09] = "CreateResourceGroup",
		["bc681469-9dd9-4bf4-9b3d-709f69efe431",0x0A] = "DeleteResourceGroup",
		["bc681469-9dd9-4bf4-9b3d-709f69efe431",0x0B] = "RenameResourceGroup",

		# locator - MSDN Ref: RPC Location Services Extensions [ms-rpcl]
		["e33c0cc4-0482-101a-bc0c-02608c6ba218",0x00] = "I_nsi_lookup_begin",
		["e33c0cc4-0482-101a-bc0c-02608c6ba218",0x01] = "I_nsi_lookup_done",
		["e33c0cc4-0482-101a-bc0c-02608c6ba218",0x02] = "I_nsi_lookup_next",
		["e33c0cc4-0482-101a-bc0c-02608c6ba218",0x03] = "I_nsi_entry_object_inq_next",
		["e33c0cc4-0482-101a-bc0c-02608c6ba218",0x04] = "I_nsi_ping_locator",
		["e33c0cc4-0482-101a-bc0c-02608c6ba218",0x05] = "I_nsi_entry_object_inq_done",
		["e33c0cc4-0482-101a-bc0c-02608c6ba218",0x06] = "I_nsi_entry_object_inq_begin",

		# lsacap - MSDN Ref: Central Access Policy Identifier Retreival Protocol [ms-capr]
		["afc07e2e-311c-4435-808c-c483ffeec7c9",0x00] = "LsarGetAvailableCAPIDs",

		# NetEventForwarder - MSDN Ref: Live Remote Event Capture Protocol [ms-lrec]
		["22e5386d-8b12-4bf0-b0ec-6a1ea419e366",0x00] = "RpcNetEventOpenSession",
		["22e5386d-8b12-4bf0-b0ec-6a1ea419e366",0x01] = "RpcNetEventReceiveData",
		["22e5386d-8b12-4bf0-b0ec-6a1ea419e366",0x02] = "RpcNetEventCloseSession",

		# NtFrsApi - MSDN Ref: File Replication Service Protocol [ms-frs1]
		["d049b186-814f-11d1-9a3c-00c04fc9b232",0x00] = "Opnum0NotUsedOnWire",
		["d049b186-814f-11d1-9a3c-00c04fc9b232",0x01] = "Opnum1NotUsedOnWire",
		["d049b186-814f-11d1-9a3c-00c04fc9b232",0x02] = "Opnum2NotUsedOnWire",
		["d049b186-814f-11d1-9a3c-00c04fc9b232",0x03] = "Opnum3NotUsedOnWire",
		["d049b186-814f-11d1-9a3c-00c04fc9b232",0x04] = "NtFrsApi_Rpc_Set_DsPollingIntervalW",
		["d049b186-814f-11d1-9a3c-00c04fc9b232",0x05] = "NtFrsApi_Rpc_Get_DsPollingIntervalW",
		["d049b186-814f-11d1-9a3c-00c04fc9b232",0x06] = "Opnum6NotUsedOnWire",
		["d049b186-814f-11d1-9a3c-00c04fc9b232",0x07] = "NtFrsApi_Rpc_InfoW",
		["d049b186-814f-11d1-9a3c-00c04fc9b232",0x08] = "NtFrsApi_Rpc_IsPathReplicated",
		["d049b186-814f-11d1-9a3c-00c04fc9b232",0x09] = "NtFrsApi_Rpc_WriterCommand",
		["d049b186-814f-11d1-9a3c-00c04fc9b232",0x0A] = "NtFrsApi_Rpc_ForceReplication",

		# RCMListener - MSDN Ref: Terminal Services Runtime Interface Protocol [ms-tsts]
		["497d95a6-2d27-4bf5-9bbd-a6046957133c",0x00] = "RpcOpenListener",
		["497d95a6-2d27-4bf5-9bbd-a6046957133c",0x01] = "RpcCloseListener",
		["497d95a6-2d27-4bf5-9bbd-a6046957133c",0x02] = "RpcStopListener",
		["497d95a6-2d27-4bf5-9bbd-a6046957133c",0x03] = "RpcStartListener",
		["497d95a6-2d27-4bf5-9bbd-a6046957133c",0x04] = "RpcIsListening",

		# RCMPublic - MSDN Ref: Terminal Services Runtime Interface Protocol [ms-tsts]
		["bde95fdf-eee0-45de-9e12-e5a61cd0d4fe",0x00] = "RpcGetClientData",
		["bde95fdf-eee0-45de-9e12-e5a61cd0d4fe",0x01] = "RpcGetConfigData",
		["bde95fdf-eee0-45de-9e12-e5a61cd0d4fe",0x02] = "RpcGetProtocolStatus",
		["bde95fdf-eee0-45de-9e12-e5a61cd0d4fe",0x03] = "RpcGetLastInputTime",
		["bde95fdf-eee0-45de-9e12-e5a61cd0d4fe",0x04] = "RpcGetRemoteAddress",
		["bde95fdf-eee0-45de-9e12-e5a61cd0d4fe",0x05] = "Opnum5NotUsedOnWire",
		["bde95fdf-eee0-45de-9e12-e5a61cd0d4fe",0x06] = "Opnum6NotUsedOnWire",
		["bde95fdf-eee0-45de-9e12-e5a61cd0d4fe",0x07] = "Opnum7NotUsedOnWire",
		["bde95fdf-eee0-45de-9e12-e5a61cd0d4fe",0x08] = "RpcGetAllListeners",
		["bde95fdf-eee0-45de-9e12-e5a61cd0d4fe",0x09] = "RpcGetSessionProtocolLastInputTime",
		["bde95fdf-eee0-45de-9e12-e5a61cd0d4fe",0x0A] = "RpcGetUserCertificates",
		["bde95fdf-eee0-45de-9e12-e5a61cd0d4fe",0x0B] = "RpcQuerySessionData",

		# RemoteFW - MSDN Ref: Firewall and Advanced Security Protocol [ms-fasp]
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x00] = "RRPC_FWOpenPolicyStore",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x01] = "RRPC_FWClosePolicyStore",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x02] = "RRPC_FWRestoreDefaults",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x03] = "RRPC_FWGetGlobalConfig",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x04] = "RRPC_FWSetGlobalConfig",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x05] = "RRPC_FWAddFirewallRule",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x06] = "RRPC_FWSetFirewallRule",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x07] = "RRPC_FWDeleteFirewallRule",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x08] = "RRPC_FWDeleteAllFirewallRules",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x09] = "RRPC_FWEnumFirewallRules",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x0A] = "RRPC_FWGetConfig",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x0B] = "RRPC_FWSetConfig",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x0C] = "RRPC_FWAddConnectionSecurityRule",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x0D] = "RRPC_FWSetConnectionSecurityRule",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x0E] = "RRPC_FWDeleteConnectionSecurityRule",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x0F] = "RRPC_FWEnumConnectionSecurityRules",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x10] = "RRPC_FWEnumConnectionSecurityRules",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x11] = "RRPC_FWAddAuthenticationSet",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x12] = "RRPC_FWSetAuthenticationSet",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x13] = "RRPC_FWDeleteAuthenticationSet",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x14] = "RRPC_FWDeleteAllAuthenticationSets",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x15] = "RRPC_FWEnumAuthenticationSets",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x16] = "RRPC_FWAddCryptoSet",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x17] = "RRPC_FWSetCryptoSet",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x18] = "RRPC_FWDeleteCryptoSet",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x19] = "RRPC_FWDeleteAllCryptoSets",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x1A] = "RRPC_FWEnumCryptoSets",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x1B] = "RRPC_FWEnumPhase1SAs",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x1C] = "RRPC_FWEnumPhase2SAs",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x1D] = "RRPC_FWDeletePhase1SAs",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x1E] = "RRPC_FWDeletePhase2SAs",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x1F] = "RRPC_FWEnumProducts",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x20] = "RRPC_FWAddMainModeRule",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x21] = "RRPC_FWSetMainModeRule",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x22] = "RRPC_FWDeleteMainModeRule",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x23] = "RRPC_FWDeleteAllMainModeRules",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x24] = "RRPC_FWEnumMainModeRules",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x25] = "RRPC_FWQueryFirewallRules",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x26] = "RRPC_FWQueryConnectionSecurityRules",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x27] = "RRPC_FWQueryMainModeRules",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x28] = "RRPC_FWQueryAuthenticationSets",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x29] = "RRPC_FWQueryCryptoSets",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x2A] = "RRPC_FWEnumNetworks",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x2B] = "RRPC_FWEnumAdapters",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x2C] = "RRPC_FWGetGlobalConfig2_10",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x2D] = "RRPC_FWGetConfig2_10",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x2E] = "RRPC_FWAddFirewallRule2_10",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x2F] = "RRPC_FWSetFirewallRule2_10",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x30] = "RRPC_FWEnumFirewallRules2_10",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x31] = "RRPC_FWAddConnectionSecurityRule2_10",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x32] = "RRPC_FWSetConnectionSecurityRule2_10",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x33] = "RRPC_FWEnumConnectionSecurityRules2_10",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x34] = "RRPC_FWAddAuthenticationSet2_10",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x35] = "RRPC_FWSetAuthenticationSet2_10",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x36] = "RRPC_FWEnumAuthenticationSets2_10",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x37] = "RRPC_FWAddCryptoSet2_10",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x38] = "RRPC_FWSetCryptoSet2_10",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x39] = "RRPC_FWEnumCryptoSets2_10",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x3A] = "RRPC_FWAddConnectionSecurityRule2_20",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x3B] = "RRPC_FWSetConnectionSecurityRule2_20",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x3C] = "RRPC_FWEnumConnectionSecurityRules2_20",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x3D] = "RRPC_FWQueryConnectionSecurityRules2_20",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x3E] = "RRPC_FWAddAuthenticationSet2_20",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x3F] = "RRPC_FWEnumAuthenticationSets2_20",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x40] = "RRPC_FWQueryAuthenticationSets2_20",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x41] = "RRPC_FWAddFirewallRule2_20",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x42] = "RRPC_FWSetFirewallRule2_20",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x43] = "RRPC_FWEnumFirewallRules2_20",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x45] = "RRPC_FWQueryFirewallRules2_20",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x46] = "RRPC_FWAddFirewallRule2_24",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x47] = "RRPC_FWSetFirewallRule2_24",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x48] = "RRPC_FWEnumFirewallRules2_24",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x49] = "RRPC_FWQueryFirewallRules2_24",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x4A] = "RRPC_FWAddFirewallRule2_25",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x4B] = "RRPC_FWSetFirewallRule2_25",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x4C] = "RRPC_FWEnumFirewallRules2_25",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x4D] = "RRPC_FWQueryFirewallRules2_25",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x4E] = "RRPC_FWAddFirewallRule2_26",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x4F] = "RRPC_FWSetFirewallRule2_26",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x50] = "RRPC_FWEnumFirewallRules2_26",
		["6b5bdd1e-528c-422c-af8c-a4079be4fe48",0x51] = "RRPC_FWQueryFirewallRules2_26",

		# remotesp - MSDN Ref: Telephony Remote Protocol [ms-trp]
		["2f5f6521-ca47-1068-b319-00dd010662db",0x00] = "RemoteSPAttach",
		["2f5f6521-ca47-1068-b319-00dd010662db",0x01] = "RemoteSPEventProc",
		["2f5f6521-ca47-1068-b319-00dd010662db",0x02] = "RemoteSPDetach",

		# SessEnvPublicRpc - MSDN Ref: Terminal Services Runtime Interface Protocol [ms-tsts]
		["1257b580-ce2f-4109-82d6-a9459d0bf6bc",0x00] = "RpcShadow2",

		# ssdpsrv - Marchand Ref: Simple Service Discovery Protocol (SSDP) [ssdp]
		["4b112204-0e19-11d3-b42b-0000f81feb9f",0x00] = "RegisterServiceRpc",
		["4b112204-0e19-11d3-b42b-0000f81feb9f",0x01] = "DeregisterServiceRpcByUSN",
		["4b112204-0e19-11d3-b42b-0000f81feb9f",0x02] = "DeregisterServiceRpc",
		["4b112204-0e19-11d3-b42b-0000f81feb9f",0x03] = "UpdateCacheRpc",
		["4b112204-0e19-11d3-b42b-0000f81feb9f",0x04] = "LookupCacheRpc",
		["4b112204-0e19-11d3-b42b-0000f81feb9f",0x05] = "CleanupCacheRpc",
		["4b112204-0e19-11d3-b42b-0000f81feb9f",0x06] = "InitializeSyncHandle",
		["4b112204-0e19-11d3-b42b-0000f81feb9f",0x07] = "RemoveSyncHandle",
		["4b112204-0e19-11d3-b42b-0000f81feb9f",0x08] = "RegisterNotificationRpc",
		["4b112204-0e19-11d3-b42b-0000f81feb9f",0x09] = "GetNotificationRpc",
		["4b112204-0e19-11d3-b42b-0000f81feb9f",0x0A] = "WakeupGetNotificationRpc",
		["4b112204-0e19-11d3-b42b-0000f81feb9f",0x0B] = "DeregisterNotificationRpc",
		["4b112204-0e19-11d3-b42b-0000f81feb9f",0x0C] = "EnableDeviceHost",
		["4b112204-0e19-11d3-b42b-0000f81feb9f",0x0D] = "DisableDeviceHost",
		["4b112204-0e19-11d3-b42b-0000f81feb9f",0x0E] = "SetICSInterfaces",
		["4b112204-0e19-11d3-b42b-0000f81feb9f",0x0F] = "SetICSOff",

		# tapsrv - MSDN Ref: Telephony Remote Protocol [ms-trp]
		["2f5f6520-ca46-1067-b319-00dd010662da",0x00] = "ClientAttach",
		["2f5f6520-ca46-1067-b319-00dd010662da",0x01] = "ClientRequest",
		["2f5f6520-ca46-1067-b319-00dd010662da",0x02] = "ClientDetach",

		# TermServEnumeration - MSDN Ref: Terminal Services Runtime Interface Protocol [ms-tsts]
		["88143fd0-c28d-4b2b-8fef-8d882f6a9390",0x00] = "RpcOpenEnum",
		["88143fd0-c28d-4b2b-8fef-8d882f6a9390",0x01] = "RpcCloseEnum",
		["88143fd0-c28d-4b2b-8fef-8d882f6a9390",0x02] = "RpcFilterByState",
		["88143fd0-c28d-4b2b-8fef-8d882f6a9390",0x03] = "RpcFilterByCallersName",
		["88143fd0-c28d-4b2b-8fef-8d882f6a9390",0x04] = "RpcEnumAddFilter",
		["88143fd0-c28d-4b2b-8fef-8d882f6a9390",0x05] = "RpcGetEnumResult",
		["88143fd0-c28d-4b2b-8fef-8d882f6a9390",0x06] = "RpcFilterBySessionType",
		["88143fd0-c28d-4b2b-8fef-8d882f6a9390",0x07] = "Opnum7NotUsedOnWire",
		["88143fd0-c28d-4b2b-8fef-8d882f6a9390",0x08] = "RpcGetSessionIds",
		["88143fd0-c28d-4b2b-8fef-8d882f6a9390",0x09] = "RpcGetEnumResultEx",
		["88143fd0-c28d-4b2b-8fef-8d882f6a9390",0x0A] = "RpcGetAllSessions",
		["88143fd0-c28d-4b2b-8fef-8d882f6a9390",0x0B] = "RpcGetAllSessionsEx",

		# TermServNotification - MSDN Ref: Terminal Services Runtime Interface Protocol [ms-tsts]
		["11899a43-2b68-4a76-92e3-a3d6ad8c26ce",0x00] = "RpcWaitForSessionState",
		["11899a43-2b68-4a76-92e3-a3d6ad8c26ce",0x01] = "RpcRegisterAsyncNotification",
		["11899a43-2b68-4a76-92e3-a3d6ad8c26ce",0x02] = "RpcWaitAsyncNotification",
		["11899a43-2b68-4a76-92e3-a3d6ad8c26ce",0x03] = "RpcUnRegisterAsyncNotification",

		# TermSrvSession - MSDN Ref: Terminal Services Runtime Interface Protocol [ms-tsts]
		["484809d6-4239-471b-b5bc-61df8c23ac48",0x00] = "RpcWaitForSessionState",
		["484809d6-4239-471b-b5bc-61df8c23ac48",0x01] = "RpcRegisterAsyncNotification",
		["484809d6-4239-471b-b5bc-61df8c23ac48",0x02] = "RpcWaitAsyncNotification",
		["484809d6-4239-471b-b5bc-61df8c23ac48",0x03] = "RpcUnRegisterAsyncNotification",

		# trksvr - MSDN Ref: Distributed Link Tracking: Central Manager Protocol [ms-dltm]
		["4da1c422-943d-11d1-acae-00c04fc2aa3f",0x00] = "LnkSvrMessage",
		["4da1c422-943d-11d1-acae-00c04fc2aa3f",0x01] = "LnkSvrMessageCallback",

		# trkwks - MSDN Ref: Distributed Link Tracking: Workstation Protocol [ms-dltw]
		["300f3532-38cc-11d0-a3f0-0020af6b0add",0x00] = "Opnum0NotUsedOnWire",
		["300f3532-38cc-11d0-a3f0-0020af6b0add",0x01] = "Opnum1NotUsedOnWire",
		["300f3532-38cc-11d0-a3f0-0020af6b0add",0x02] = "Opnum2NotUsedOnWire",
		["300f3532-38cc-11d0-a3f0-0020af6b0add",0x03] = "Opnum3NotUsedOnWire",
		["300f3532-38cc-11d0-a3f0-0020af6b0add",0x04] = "Opnum4NotUsedOnWire",
		["300f3532-38cc-11d0-a3f0-0020af6b0add",0x05] = "Opnum5NotUsedOnWire",
		["300f3532-38cc-11d0-a3f0-0020af6b0add",0x06] = "Opnum6NotUsedOnWire",
		["300f3532-38cc-11d0-a3f0-0020af6b0add",0x07] = "Opnum7NotUsedOnWire",
		["300f3532-38cc-11d0-a3f0-0020af6b0add",0x08] = "Opnum8NotUsedOnWire",
		["300f3532-38cc-11d0-a3f0-0020af6b0add",0x09] = "Opnum9NotUsedOnWire",
		["300f3532-38cc-11d0-a3f0-0020af6b0add",0x0A] = "Opnum10NotUsedOnWire",
		["300f3532-38cc-11d0-a3f0-0020af6b0add",0x0B] = "Opnum11NotUsedOnWire",
		["300f3532-38cc-11d0-a3f0-0020af6b0add",0x0C] = "LnkSearchMachine",

		# TsProxyRpcInterface - MSDN Ref: Terminal Services Gateway Server Protocol [ms-tsgu]
		["44e265dd-7daf-42cd-8560-3cdb6e7a2729",0x00] = "Opnum0NotUsedOnWire",
		["44e265dd-7daf-42cd-8560-3cdb6e7a2729",0x01] = "TsProxyCreateTunnel",
		["44e265dd-7daf-42cd-8560-3cdb6e7a2729",0x02] = "TsProxyAuthorizeTunnel",
		["44e265dd-7daf-42cd-8560-3cdb6e7a2729",0x03] = "TsProxyMakeTunnelCall",
		["44e265dd-7daf-42cd-8560-3cdb6e7a2729",0x04] = "TsProxyCreateChannel",
		["44e265dd-7daf-42cd-8560-3cdb6e7a2729",0x05] = "Opnum5NotUsedOnWire",
		["44e265dd-7daf-42cd-8560-3cdb6e7a2729",0x06] = "TsProxyCloseChannel",
		["44e265dd-7daf-42cd-8560-3cdb6e7a2729",0x07] = "TsProxyCloseTunnel",
		["44e265dd-7daf-42cd-8560-3cdb6e7a2729",0x08] = "TsProxySetupReceivePipe",
		["44e265dd-7daf-42cd-8560-3cdb6e7a2729",0x09] = "TsProxySendToServer",

		# TSVIPPublic - MSDN Ref: Terminal Services Runtime Interface Protocol [ms-tsts]
		["53b46b02-c73b-4a3e-8dee-b16b80672fc0",0x00] = "RpcGetSessionIP",

		# W32Time - MSDN Ref: W32Time Remote Protocol [ms-w32t]
		["8fb6d884-2388-11d0-8c35-00c04fda2795",0x00] = "W32TimeSync",
		["8fb6d884-2388-11d0-8c35-00c04fda2795",0x01] = "W32TimeGetNetlogonServiceBits",
		["8fb6d884-2388-11d0-8c35-00c04fda2795",0x02] = "W32TimeQueryProviderStatus",
		["8fb6d884-2388-11d0-8c35-00c04fda2795",0x03] = "W32TimeQuerySource",
		["8fb6d884-2388-11d0-8c35-00c04fda2795",0x04] = "W32TimeQueryProviderConfiguration",
		["8fb6d884-2388-11d0-8c35-00c04fda2795",0x05] = "W32TimeQueryConfiguration",
		["8fb6d884-2388-11d0-8c35-00c04fda2795",0x06] = "W32TimeQueryStatus",
		["8fb6d884-2388-11d0-8c35-00c04fda2795",0x07] = "W32TimeLog",

		# WdsRpcInterface - MSDN Ref: Windows Deployment Services Control Protocol [ms-wdsc]
		["1a927394-352e-4553-ae3f-7cf4aafca620",0x00] = "WdsRpcMessage",

		# winsi2 - MSDN Ref: Remote Administrative Interface: WINS [ms-raiw]
		["811109bf-a4e1-11d1-ab54-00a0c91e9b45",0x00] = "R_WinsTombstoneDbRecs",
		["811109bf-a4e1-11d1-ab54-00a0c91e9b45",0x01] = "R_WinsCheckAccess",

		# Witness - MSDN Ref: Service Witness Protocol [ms-swn]
		["ccd8c074-d0e5-4a40-92b4-d074faa6ba28",0x00] = "WitnessrGetInterfaceList",
		["ccd8c074-d0e5-4a40-92b4-d074faa6ba28",0x01] = "WitnessrRegister",
		["ccd8c074-d0e5-4a40-92b4-d074faa6ba28",0x02] = "WitnessrUnRegister",
		["ccd8c074-d0e5-4a40-92b4-d074faa6ba28",0x03] = "WitnessrAsyncNotify",
		["ccd8c074-d0e5-4a40-92b4-d074faa6ba28",0x04] = "WitnessrRegisterEx",
	} &redef;
}

#end bzar_dce-rpc_consts.zeek
