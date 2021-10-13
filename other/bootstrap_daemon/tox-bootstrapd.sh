#! /bin/bash
### BEGIN INIT INFO
# Provides:          tox-bootstrapd
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Starts the Tox DHT bootstrapping server daemon
# Description:       Starts the Tox DHT bootstrapping server daemon
### END INIT INFO

# PATH should only include /usr/* if it runs after the mountnfs.sh script
PATH=/sbin:/usr/sbin:/bin:/usr/bin
DESC="Tox DHT bootstrap daemon"
NAME=tox-bootstrapd
DAEMON=/usr/local/bin/$NAME
CFGFILE=/etc/$NAME.conf
DAEMON_ARGS="--config $CFGFILE"
PIDDIR=/var/run/$NAME
PIDFILE=$PIDDIR/$NAME.pid
SCRIPTNAME=/etc/init.d/$NAME
USER=tox-bootstrapd
GROUP=tox-bootstrapd

# Set ulimit -n based on number of fds available.
# This check is borrowed from Debian's tor package, with a few modifications.
if [ -r /proc/sys/fs/file-max ]; then
	system_max=$(cat /proc/sys/fs/file-max)
	if [ "$system_max" -gt "80000" ] ; then
		MAX_FILEDESCRIPTORS=32768
	elif [ "$system_max" -gt "40000" ] ; then
		MAX_FILEDESCRIPTORS=16384
	elif [ "$system_max" -gt "20000" ] ; then
		MAX_FILEDESCRIPTORS=8192
	elif [ "$system_max" -gt "10000" ] ; then
		MAX_FILEDESCRIPTORS=4096
	else
		MAX_FILEDESCRIPTORS=1024
		cat << EOF

Warning: Your system has very few file descriptors available in total.

Maybe you should try raising that by adding 'fs.file-max=100000' to your
/etc/sysctl.conf file.  Feel free to pick any number that you deem appropriate.
Then run 'sysctl -p'.  See /proc/sys/fs/file-max for the current value, and
file-nr in the same directory for how many of those are used at the moment.

EOF
	fi
else
	MAX_FILEDESCRIPTORS=32768
fi

# Exit if the package is not installed
[ -x "$DAEMON" ] || exit 0

# Load the VERBOSE setting and other rcS variables
. /lib/init/vars.sh

# Define LSB log_* functions.
# Depend on lsb-base (>= 3.2-14) to ensure that this file is present
# and status_of_proc is working.
. /lib/lsb/init-functions

#
# Function that starts the daemon/service
#
do_start()
{
	# Return
	#   0 if daemon has been started
	#   1 if daemon was already running
	#   2 if daemon could not be started
	if [ ! -d $PIDDIR ]
	then
		mkdir $PIDDIR
	fi
	chown $USER:$GROUP $PIDDIR
	start-stop-daemon --start --quiet --pidfile $PIDFILE --exec $DAEMON --test --chuid $USER > /dev/null || return 1
	# TCP Server needs to be able to have lots of TCP sockets open.
	ulimit -n $MAX_FILEDESCRIPTORS
	start-stop-daemon --start --quiet --pidfile $PIDFILE --exec $DAEMON --chuid $USER -- $DAEMON_ARGS || return 2
}

#
# Function that stops the daemon/service
#
do_stop()
{
	# Return
	#   0 if daemon has been stopped
	#   1 if daemon was already stopped
	#   2 if daemon could not be stopped
	#   other if a failure occurred
	start-stop-daemon --stop --quiet --retry 5 --pidfile $PIDFILE --name $NAME --chuid $USER
	RETVAL="$?"
	[ "$RETVAL" = 2 ] && return 2
	# Many daemons don't delete their pidfiles when they exit.
	rm -f $PIDFILE
	return "$RETVAL"
}

case "$1" in
  start)
	[ "$VERBOSE" != no ] && log_daemon_msg "Starting $DESC" "$NAME"
	do_start
	case "$?" in
		0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
		2) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
	esac
	;;
  stop)
	[ "$VERBOSE" != no ] && log_daemon_msg "Stopping $DESC" "$NAME"
	do_stop
	case "$?" in
		0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
		2) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
	esac
	;;
  status)
	status_of_proc -p $PIDFILE "$DAEMON" "$NAME" && exit 0 || exit $?
	;;

  restart)
	log_daemon_msg "Restarting $DESC" "$NAME"
	do_stop
	case "$?" in
	  0|1)
		do_start
		case "$?" in
			0) log_end_msg 0 ;;
			1) log_end_msg 1 ;; # Old process is still running
			*) log_end_msg 1 ;; # Failed to start
		esac
		;;
	  *)
		# Failed to stop
		log_end_msg 1
		;;
	esac
	;;
  *)
	echo "Usage: $SCRIPTNAME {start|stop|status|restart}" >&2
	exit 3
	;;
esac
exit 0
