module cron;

export {
	## the cron log identifier
	redef enum Log::ID += { JOBS_LOG };

	type CronJob: record {
		## the command to execute on an interval
		command:	Exec::Command;
		## how long to wait before executing
		i:			interval;
		## whether or not to keep rescheduling
		reschedule: bool &default=T;
	};

	type JobInfo: record {
		## the current time
		ts:			time &log;
		## the command that was executed
		command:	string &log;
		## the result of executing the command
		result:		vector of string &log;
		## the result code of the command
		exit_code:  count &log;
	};

	## Event to schedule a cron task
	global run_cron: event(job: CronJob);

	## Event for retrieving cron results
	global cron_done: event(job: CronJob, result: Exec::Result);

	## Event for logging cron
	global log_cron: event(rec: JobInfo);
}

event bro_init()
	{
	Log::create_stream(cron::JOBS_LOG, [$columns=JobInfo, $ev=log_cron, $path="cron"]);
	}

event run_cron(job: CronJob)
	{
	when ( local result = Exec::run(job$command) )
		{
		event cron::cron_done(job, result);
		}
	}

event cron_done(job: CronJob, result: Exec::Result)
	{
	if ( job$reschedule )
		{
		schedule job$i { run_cron(job) };
		}
	}

event cron_done(job: CronJob, result: Exec::Result)
	{
	local info = JobInfo($ts=network_time(), 
		$command=job$command$cmd, 
		$result=result$stdout, 
		$exit_code=result$exit_code);
	Log::write(cron::JOBS_LOG, info);
	}