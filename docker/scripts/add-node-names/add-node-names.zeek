##! Adds cluster node name to logs.

module NodeName;

export {
	## Enables node names for all active streams
	const enable_all_logs = F &redef;
	## Streams not to add node names for
	const exclude_logs: set[Log::ID] = { } &redef;
	## Streams to add node names for
	const include_logs: set[Log::ID] = { Conn::LOG } &redef;
}

@if ( Cluster::is_enabled() )

type AddedFields: record {
	node_name: string &log;
};

function node_name_ext_func(path: string): AddedFields
	{
	return AddedFields($node_name = Cluster::node);
	}

event bro_init() &priority=-3
	{
	# Add ext_func to log streams
	for ( id in Log::active_streams )
		{
		if ( (enable_all_logs || (id in include_logs)) && (id !in exclude_logs) )
			{
			local filter = Log::get_filter(id, "default");
			filter$ext_func = node_name_ext_func;
			Log::add_filter(id, filter);
			}
		}
	}

@else

event bro_init()
	{
	Reporter::warning("Node names are not added to logs (not in cluster mode)!");
	}

@endif