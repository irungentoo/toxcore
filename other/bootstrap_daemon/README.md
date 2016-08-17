#Instructions

- [For `systemd` users](#systemd)
  - [Setting up](#systemd-setting-up)
  - [Updating](#systemd-updating)
  - [Troubleshooting](#systemd-troubleshooting)
<br>
- [For `SysVinit` users](#sysvinit)
  - [Setting up](#sysvinit-setting-up)
  - [Updating](#sysvinit-updating)
  - [Troubleshooting](#sysvinit-troubleshooting)
<br>
- [For `Docker` users](#docker)
  - [Setting up](#docker-setting-up)
  - [Updating](#docker-updating)
  - [Troubleshooting](#docker-troubleshooting)


These instructions are primarily tested on Debian Linux, Wheezy for SysVinit and Jessie for systemd, but they should work on other POSIX-compliant systems too.


<a name="systemd" />
##For `systemd` users

<a name="systemd-setting-up" />
###Setting up

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

Get your public key and check that the daemon initialized correctly:
```sh
sudo grep "tox-bootstrapd" /var/log/syslog
```

<a name="systemd-updating" />
###Updating

You want to make sure that the daemon uses the newest toxcore, as there might have been some changes done to the DHT, so it's advised to update the daemon at least once every month.

To update the daemon first stop it:

```sh
sudo systemctl stop tox-bootstrapd.service
```

Then update your toxcore git repository, rebuild the toxcore and the daemon and make sure to install them.

Check if `tox-bootstrapd.service` in toxcore git repository was modified since the last time you copied it, as you might need to update it too.

After all of this is done, simply start the daemon back again:

```sh
sudo systemctl start tox-bootstrapd.service
```

Note that `tox-bootstrapd.service` file might

<a name="systemd-troubleshooting" />
###Troubleshooting

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


<a name="sysvinit" />
##For `SysVinit` users

<a name="sysvinit-setting-up" />
###Setting up

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

If you have configured the daemon to use any port numbers that are lower than 1024, you need to execute the command below, as by default non-privileged users cannot open ports <1024. The change persists through reboot:

```sh
sudo setcap CAP_NET_BIND_SERVICE=+eip /usr/local/bin/tox-bootstrapd
```

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

Get your public key and check that the daemon initialized correctly:
```sh
sudo grep "tox-bootstrapd" /var/log/syslog
```

<a name="sysvinit-updating" />
###Updating

You want to make sure that the daemon uses the newest toxcore, as there might have been some changes done to the DHT, so it's advised to update the daemon at least once every month.

To update the daemon first stop it:

```sh
sudo service tox-bootstrapd stop
```

Then update your toxcore git repository, rebuild the toxcore and the daemon and make sure to install them.

Check if `tox-bootstrapd.sh` in toxcore git repository was modified since the last time you copied it, as you might need to update it too.

After all of this is done, simply start the daemon back again:

```sh
sudo service tox-bootstrapd start
```

<a name="sysvinit-troubleshooting" />
###Troubleshooting

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


<a name="docker" />
##For `Docker` users:

<a name="docker-setting-up" />
###Setting up

If you are familiar with Docker and would rather run the daemon in a Docker container, run the following from this directory:

```sh
sudo docker build -t tox-bootstrapd docker/

sudo useradd --home-dir /var/lib/tox-bootstrapd --create-home --system --shell /sbin/nologin --comment "Account to run Tox's DHT bootstrap daemon" --user-group tox-bootstrapd
sudo chmod 700 /var/lib/tox-bootstrapd

sudo docker run -d --name tox-bootstrapd --restart always -v /var/lib/tox-bootstrapd/:/var/lib/tox-bootstrapd/ -p 443:443 -p 3389:3389 -p 33445:33445 -p 33445:33445/udp tox-bootstrapd
```

We create a new user and protect its home directory in order to mount it in the Docker image, so that the kyepair the daemon uses would be stored on the host system, which makes it less likely that you would loose the keypair while playing with or updating the Docker container.

You can check logs for your public key or any errors:
```sh
sudo docker logs tox-bootstrapd
```

Note that the Docker container runs a script which pulls a list of bootstrap nodes off https://nodes.tox.chat/ and adds them in the config file.

<a name="docker-updating" />
###Updating

You want to make sure that the daemon uses the newest toxcore, as there might have been some changes done to the DHT, so it's advised to update the daemon at least once every month.

To update the daemon, all you need is to erase current container with its image:

```sh
sudo docker stop tox-bootstrapd
sudo docker rm tox-bootstrapd
sudo docker rmi tox-bootstrapd
```

Then rebuild and run the image again:

```sh
sudo docker build -t tox-bootstrapd docker/
sudo docker run -d --name tox-bootstrapd --restart always -v /var/lib/tox-bootstrapd/:/var/lib/tox-bootstrapd/ -p 443:443 -p 3389:3389 -p 33445:33445 -p 33445:33445/udp tox-bootstrapd
```

<a name="docker-troubleshooting" />
###Troubleshooting

- Check if the container is running:
```sh
sudo docker ps -a
```

- Check the log for errors:
```sh
sudo docker logs tox-bootstrapd
```
