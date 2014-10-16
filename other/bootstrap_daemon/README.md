##Instructions for Debian

For security reasons we run the daemon under its own user.
Create a new user by executing the following:
```sh
sudo useradd --system --shell /sbin/nologin --comment "Account to run Tox's DHT bootstrap daemon" --user-group tox-bootstrapd
```

Create a directory where the daemon will store its keys:
```sh
sudo mkdir /var/lib/tox-bootstrapd/
```

Restrain other users from accessing the directory:
```sh
sudo chown tox-bootstrapd:tox-bootstrapd /var/lib/tox-bootstrapd/
sudo chmod 700 /var/lib/tox-bootstrapd/
```

Look at the variable declarations in the beginning of `tox-bootstrapd.sh` init script to see if you need to change anything for it to work for you. The default values must be fine for most users and we assume that you use those next.

Go over everything in `tox-bootstrapd.conf`. Make sure `pid_file_path` matches `PIDFILE` from `tox-bootstrapd.sh`.

Place `tox-bootstrapd.conf` file to where `CFGFILE` variable from `tox-bootstrapd.sh` tells. By default it's `/etc/tox-bootstrapd.conf`.

Place `tox-bootstrapd.sh` init file at `/etc/init.d/tox-bootstrapd` (note the disappearance of ".sh" ending).

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

- Make sure `pid_file_path` in `/etc/tox-bootstrapd.conf` matches `PIDFILE` from  `/etc/init.d/tox-bootstrapd`.

- Make sure you have write permission for keys and pid files.

- Make sure you have read permission for the config file.
