Instructions for Debian

The following commands are to be executed as root:

1. In `tox-dht-bootstrap-server-daemon` file change:
  - `CFG` to where your config file (`conf`) will be; read rights required
  - `DAEMON` to point to the executable
  - `PIDFILE` to point to a pid file daemon would have rights to create

2. Go over everything in `conf`. Make sure `pid_file_path` matches `PIDFILE` from `tox-dht-bootstrap-server-daemon`

3. Execute: `mv tox-dht-bootstrap-server-daemon /etc/init.d/tox-dht-bootstrap-server-daemon`

4. Give the right permissions to this file: `chmod 755 /etc/init.d/tox-dht-bootstrap-server-daemon`

5. Execute: `update-rc.d tox-dht-bootstrap-server-daemon defaults`

6. Start the service: `service tox-dht-bootstrap-server-daemon start`

7. Verify that the service is running: `service tox-dht-bootstrap-server-daemon status`

You can see daemon's log with `grep "tox-dht-bootstrap-server-daemon" /var/log/syslog`

Troubleshooting:

1. Check the log for errors with `grep "tox-dht-bootstrap-server-daemon" /var/log/syslog`

2. Check that paths in the beginning of `/etc/init.d/tox-dht-bootstrap-server-daemon` are valid

3. Make sure that `PIDFILE` from `/etc/init.d/tox-dht-bootstrap-server-daemon` matches with the `pid_file_path` from `conf`

4. Make sure you have write premmision to keys and pid files

5. Make sure you have read premission to config file