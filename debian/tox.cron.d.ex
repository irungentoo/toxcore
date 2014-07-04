#
# Regular cron jobs for the tox package
#
0 4	* * *	root	[ -x /usr/bin/tox_maintenance ] && /usr/bin/tox_maintenance
