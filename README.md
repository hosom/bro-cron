# Cron Module for Bro IDS
This module creates an API through which plugins can schedule commands on Bro IDS nodes. This is convenient for Bro packages that require regularly scheduled commands, since there is no convenient way to package a cron job. 

## Usage

### Scheduling a task on all nodes

```
event bro_init() &priority=-10
	{
    local c = cron::CronJob($command=Exec::Command($cmd="whoami"), $i=3sec, $reschedule=T);
	event cron::run_cron(c);
	}
```

### Scheduling on only the manager node

```
@load base/frameworks/cluster

@if ( Cluster::local_node_type() == Cluster::MANAGER )
event bro_init() &priority=-10
	{
    local c = cron::CronJob($command=Exec::Command($cmd="whoami"), $i=3sec, $reschedule=T);
	event cron::run_cron(c);
	}
@endif
```