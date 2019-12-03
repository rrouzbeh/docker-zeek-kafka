##! Adds cluster node's interface to logs.

module AddInterfaces;

export {
	## Enables interfaces for all active streams
	const enable_all_logs = F &redef;
	## Streams not to add interfaces for
	const exclude_logs: set[Log::ID] = { } &redef;
	## Streams to add interfaces for
	const include_logs: set[Log::ID] = { Conn::LOG } &redef;
}

@if ( Cluster::is_enabled() )

type AddedFields: record {
	interface: string &log;
};

function interface_ext_func(path: string): AddedFields
	{
	if ( Cluster::nodes[Cluster::node]?$interface )
		return AddedFields($interface = Cluster::nodes[Cluster::node]$interface);
	}

event bro_init() &priority=-3
	{
	# Add ext_func to log streams
	for ( id in Log::active_streams )
		{
		if ( (enable_all_logs || (id in include_logs)) && (id !in exclude_logs) )
			{
			local filter = Log::get_filter(id, "default");
			filter$ext_func = interface_ext_func;
			Log::add_filter(id, filter);
			}
		}
	}

@else

event bro_init()
	{
	Reporter::warning("Interfaces are not added to logs (not in cluster mode)!");
	}

@endif