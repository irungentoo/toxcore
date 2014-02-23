##Instructions for Debian

The following commands are to be executed as root:

1. In `tox_bootstrap_daemon.sh` file change:
  - `CFG` to where your config file (`conf`) will be; read rights required
  - `DAEMON` to point to the executable
  - `PIDFILE` to point to a pid file daemon would have rights to create

2. Go over everything in `conf`. Make sure `pid_file_path` matches `PIDFILE` from `tox_bootstrap_daemon.sh`

3. Execute: 
```
mv tox_bootstrap_daemon.sh /etc/init.d/tox_bootstrap_daemon
```
*(note that we removed `.sh` ending)*

4. Give the right permissions to this file: 
```
chmod 755 /etc/init.d/tox_bootstrap_daemon
```

5. Execute: 
```
update-rc.d tox_bootstrap_daemon defaults
```

6. Start the service: 
```
service tox_bootstrap_daemon start
```

7. Verify that the service is running: 
```
service tox_bootstrap_daemon status
```

--

You can see daemon's log with
```
grep "tox_bootstrap_daemon" /var/log/syslog
```

**Note that system log is where you find your public key**

--

###Troubleshooting:

1. Check the log for errors with 
```
grep "tox_bootstrap_daemon" /var/log/syslog
```

2. Check that paths in the beginning of `/etc/init.d/tox_bootstrap_daemon` are valid

3. Make sure that `PIDFILE` from `/etc/init.d/tox_bootstrap_daemon` matches with the `pid_file_path` from `conf`

4. Make sure you have write permission to keys and pid files

5. Make sure you have read permission for config file