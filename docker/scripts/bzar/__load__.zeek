#
# File: __load__.bro
# Created: 20180701
# Updated: 20190225
#
# Copyright 2018 The MITRE Corporation.  All Rights Reserved.
# Approved for public release.  Distribution unlimited.  Case number 18-2489.
#

@load ./main.zeek
@load ./bzar_dce-rpc_consts.zeek
@load ./bzar_dce-rpc.zeek
@load ./bzar_smb.zeek
@load ./bzar_files.zeek

@load-sigs ./dpd.sig

#end __load__.bro
