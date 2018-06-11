### TVHEADEND with PVU support ###

Install OSCAM-EMU
```
cd oscam
make
cd config
cp * /usr/local/etc/.
cd ..
cd Distribution
cp ./oscam /usr/local/bin/oscam
```
Create a Daemon to run at boot:
```
sudo vim /etc/init.d/oscam
```
Insert the following code
```
#!/bin/sh
### BEGIN INIT INFO
# Provides: oscam
# Required-Start: $local_fs $network $remote_fs
# Required-Stop: $local_fs $network $remote_fs
# Default-Start:  2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: start and stop service oscam
# Description: oscam
### END INIT INFO

DAEMON=/usr/local/bin/oscam
PIDFILE=/var/run/oscam.pid
DAEMON_OPTS="-p 4096 -r 2 -B ${PIDFILE} -c /usr/local/etc/ -t /tmp/.oscam"

test -x ${DAEMON} || exit 0

. /lib/lsb/init-functions

case "$1" in
  start)
    log_daemon_msg "Starting OScam..."
    /sbin/start-stop-daemon --start --quiet --background --name oscam --exec ${DAEMON} -- ${DAEMON_OPTS}
    log_end_msg $?
    ;;
  stop)
    log_daemon_msg "Stopping OScam..."
    /sbin/start-stop-daemon -R 5 --stop --name oscam --exec ${DAEMON}
    log_end_msg $?
    ;;
  restart)
    $0 stop
    $0 start
    ;;
  force-reload)
    $0 stop
    /bin/kill -9 `pidof oscam`
    /usr/bin/killall -9 oscam
    $0 start
    ;;
  *)
    echo "Usage: /etc/init.d/oscam {start|stop|restart|force-reload}"
    exit 1
    ;;
esac
```
To “enable” the script and the starting up of oscam on reboot, use the following commands on Ubuntu/Debian:
```
sudo chmod +x /etc/init.d/oscam
sudo update-rc.d oscam defaults
```
To force detect service
```
sudo systemctl daemon-reload
sudo systemctl enable oscam
```
Reboot System and Oscam with EMU will be available at:
```
http://192.168.1.91:8888
```
TVHeadend Install
1> Dependencies:
```
sudo apt install gettext
sudo apt-get install libssl-dev
sudo apt install cmake
sudo apt install build-essential git pkg-config libssl-dev bzip2 wget libavahi-client-dev zlib1g-dev libavcodec-dev libavutil-dev libavformat-dev libswscale-dev libavresample-dev gettext cmake libiconv-hook-dev liburiparser-dev debhelper libcurl4-gnutls-dev python-minimal
sudo apt-get install libpcre3-dev
```
Clone this repo
```
cd tvheadend
./configure
sudo AUTOBUILD_CONFIGURE_EXTRA=--disable-libx265\ --disable-pie\ --disable-libvpx  ./Autobuild.sh
```
Go to root and install package
```
sudo dpkg -i tvheadend_4.1-2658~g9d85808_armhf.deb
```
Follow Directions give password
Enter Tvheadend http://192.168.1.91:9981

```
Configuration/General/Base:User interfase level: Expert
(Cas) Menu should appear
```
Configure CAs
```
Configuration/CAs/+Add/CAPMT
Enabled: [x]
Name: emu
Mode: OSCam net protocol (rev >= 10389)
Camd.socket filename / IP Address (TCP mode): 127.0.0.1 (in case of tvheadend and oscam is run on the same host)
Listen / Connect port: 2000
```
Create user pvu with password pvu
With streaming
Allowed all networks

Create Network for the satellite
Create TVadapters using network
Create muxes 
Scan Services
Map services

execute channel.sh to create channels
Open with kodi

