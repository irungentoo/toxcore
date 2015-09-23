#Instructions

- [For `systemd` users](#systemd)
  - [Troubleshooting](#systemd-troubleshooting)
<br>
- [For `init.d` users](#initd)
  - [Troubleshooting](#initd-troubleshooting)


These instructions are primarily tested on Debian Linux, Wheezy for init.d and Jessie for systemd, but they should work on other POSIX-compliant systems too.


<a name="systemd" />
##For `systemd` users:

For security reasons we run the daemon under its own user.

Create a new user by executing the following:
```sh
sudo useradd --home-dir /var/lib/tox-bootstrapd --create-home --system --shell /sbin/nologin --comment "Account to run Tox's DHT bootstrap daemon" --user-group tox-bootstrapd
```

Restrict access to home directory:
```sh
sudo chmod 700 /var/lib/tox-bootstrapd
```

Copy `tox-bootstrapd.conf` file to where `ExecStart=` from `tox-bootstrapd.service` points to. By default it's `/etc/tox-bootstrapd.conf`.
```sh
sudo cp tox-bootstrapd.conf /etc/tox-bootstrapd.conf
```

Go over everything in the copied `tox-bootstrapd.conf` file. Set options you want and add actual working nodes to the `bootstrap_nodes` list, instead of the example ones, if you want your node to connect to the Tox network. Make sure `pid_file_path` matches `PIDFile=` from `tox-bootstrapd.service`.

Copy `tox-bootstrapd.service` to `/etc/systemd/system/`:
```sh
sudo cp tox-bootstrapd.service /etc/systemd/system/
```

You must uncomment the next line in tox-bootstrapd.service, if you want to use port number < 1024 

    #CapabilityBoundingSet=CAP_NET_BIND_SERVICE

and, possibly, install `libcap2-bin` or `libcap2` package, depending of your distribution.

Reload systemd units definitions, enable service for automatic start (if needed), start it and verify it's running: 
```sh
sudo systemctl daemon-reload
sudo systemctl enable tox-bootstrapd.service
sudo systemctl start tox-bootstrapd.service
sudo systemctl status tox-bootstrapd.service
```

Get your public key and check that the daemon initialized correctly: (Your public key will be written in ``/var/log/syslog``.)
```sh
sudo grep "tox-bootstrapd" /var/log/syslog
```

<a name="systemd-troubleshooting" />
###Troubleshooting:

- Check daemon's status:
```sh
sudo systemctl status tox-bootstrapd.service
```

- Check the log for errors:
```sh
sudo grep "tox-bootstrapd" /var/log/syslog
# or
sudo journalctl --pager-end
# or
sudo journalctl -f _SYSTEMD_UNIT=tox-bootstrapd.service
```

- Make sure tox-bootstrapd user has write permission for keys and pid files.

- Make sure tox-bootstrapd has read permission for the config file.

- Make sure tox-bootstrapd location matches its path in tox-bootstrapd.service file.


<a name="initd" />
##For `init.d` users

For security reasons we run the daemon under its own user.

Create a new user by executing the following:
```sh
sudo useradd --home-dir /var/lib/tox-bootstrapd --create-home --system --shell /sbin/nologin --comment "Account to run Tox's DHT bootstrap daemon" --user-group tox-bootstrapd
```

Restrict access to home directory:
```sh
sudo chmod 700 /var/lib/tox-bootstrapd
```

Copy `tox-bootstrapd.conf` file to where `CFGFILE` variable from `tox-bootstrapd.sh` points to. By default it's `/etc/tox-bootstrapd.conf`.
```sh
sudo cp tox-bootstrapd.conf /etc/tox-bootstrapd.conf
```

Go over everything in the copied `tox-bootstrapd.conf` file. Set options you want and add actual working nodes to the `bootstrap_nodes` list, instead of the example ones, if you want your node to connect to the Tox network. Make sure `pid_file_path` matches `PIDFILE` from `tox-bootstrapd.sh`.

Look at the variable declarations in the beginning of `tox-bootstrapd.sh` init script to see if you need to change anything for it to work on your system. The default values must be fine for most users and we assume that you use those next.

Copy `tox-bootstrapd.sh` init script to `/etc/init.d/tox-bootstrapd` (note the disappearance of ".sh" ending):
```sh
sudo cp tox-bootstrapd.sh /etc/init.d/tox-bootstrapd
```

Set permissions for the init system to run the script:
```sh
sudo chmod 755 /etc/init.d/tox-bootstrapd
```

Make the init system aware of the script, start the daemon and verify it's running:
```sh
sudo update-rc.d tox-bootstrapd defaults
sudo service tox-bootstrapd start
sudo service tox-bootstrapd status
```

Get your public key and check that the daemon initialized correctly: (Your public key will be written in ``/var/log/syslog``.)
```sh
sudo grep "tox-bootstrapd" /var/log/syslog
```

<a name="initd-troubleshooting" />
###Troubleshooting:

- Check daemon's status:
```sh
sudo service tox-bootstrapd status
```

- Check the log for errors: 
```sh
sudo grep "tox-bootstrapd" /var/log/syslog
```

- Check that variables in the beginning of `/etc/init.d/tox-bootstrapd` are valid.

- Make sure tox-bootstrapd user has write permission for keys and pid files.

- Make sure tox-bootstrapd has read permission for the config file.

- Make sure tox-bootstrapd location matches its path in the `/etc/init.d/tox-bootstrapd` init script.
