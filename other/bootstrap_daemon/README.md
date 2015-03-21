##Instructions 

This instruction primarily tested on Linux but, may be, will work on other POSIX-compliant systems.

For security reasons we run the daemon under its own user.

Create a new user by executing the following:
```sh
sudo useradd --home-dir /var/lib/tox-bootstrapd --create-home --system --shell /sbin/nologin --comment "Account to run Tox's DHT bootstrap daemon" --user-group tox-bootstrapd
```

Copy `tox-bootstrapd.conf` file to where `CFGFILE` variable from `tox-bootstrapd.sh` tells (for `init.d` users) or `ExecStart=` from `tox-bootstrap.service` ( for `systemd` users). By default it's `/etc/tox-bootstrapd.conf`.

Go over everything in `tox-bootstrapd.conf`. Make sure `pid_file_path` matches `PIDFILE` from `tox-bootstrapd.sh` (`init.d`) or `PIDFile=` from `tox-bootstrap.service` AND file in `ExecStartPre`(`systemd`).


Restrict access to home directory:
```sh
sudo chmod 700 /var/lib/tox-bootstrapd
```

##For `init.d` users:

Look at the variable declarations in the beginning of `tox-bootstrapd.sh` init script to see if you need to change anything for it to work for you. The default values must be fine for most users and we assume that you use those next.

Copy `tox-bootstrapd.sh` init file to `/etc/init.d/tox-bootstrapd` (note the disappearance of ".sh" ending).
```sh
sudo cp tox-bootstrapd.sh /etc/init.d/tox-bootstrapd
```

Set permissions for the init system to run the script:
```sh
sudo chmod 755 /etc/init.d/tox-bootstrapd
```

Make the init system aware of the script:
```sh
sudo update-rc.d tox-bootstrapd defaults
```

Start the daemon:
```sh
sudo service tox-bootstrapd start
```

Verify it's running:
```sh
sudo service tox-bootstrapd status
```

Get your public key and check that the daemon initialized correctly:
```sh
sudo grep "tox-bootstrapd" /var/log/syslog
```

##For `systemd` users:

Copy tox-bootstrap.service to /etc/systemd/system/:
```sh
sudo cp tox-bootstrap.service /etc/systemd/system/
```

Make sure, that path to `chown` and `mkdir` is correct in `tox-bootstrap.service` (they may be different in some distributions, by default  `/bin/chown` and `/bin/mkdir`) 

You must uncomment the next line in tox-bootstrap.service, if you want to use port number <1024 
	
	#CapabilityBoundingSet=CAP_NET_BIND_SERVICE

and, possibly, install `libcap2-bin` or `libcap2` package, depending of your distribution.


Reload systemd units definitions, enable service for automatic start (if needed), and start it: 
```sh
sudo systemctl daemon-reload
sudo systemctl enable tox-bootstrap.service
sudo systemctl start tox-bootstrap.service
```
###Troubleshooting:

- Check daemon's status:
```sh
#init.d
sudo service tox-bootstrapd status

#systemd
sudo systemctl status tox-bootstrap.service 
```

- Check the log for errors: 
```sh
#init.d
sudo grep "tox-bootstrapd" /var/log/syslog

#systemd
sudo journalctl -f _SYSTEMD_UNIT=tox-bootstrap.service
```

`init.d`:
- Check that variables in the beginning of `/etc/init.d/tox-bootstrapd` are valid.


Common:

- Make sure tox-bootstrapd user has write permission for keys and pid files (in systemd pid file insured by unit definition).

- Make sure tox-bootstrapd has read permission for the config file.

- Make sure tox-bootstrapd location matches its path in init scripts, if you specified non-default `--prefix`, when building. 
