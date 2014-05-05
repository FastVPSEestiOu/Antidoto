Antidoto
========

Linux antimalware and antirootkit tool

Hot to run it:
```bash
wget --no-check-certificate https://raw.githubusercontent.com/pavel-odintsov/Antidoto/master/Antidoto.pl -OAntidoto.pl
perl Antidoto.pl
```

How to enable ClamAV checks: 
```bash
yum install -y clamav clamd
freshclam
wget http://www.rfxn.com/downloads/rfxn.ndb -O/var/lib/clamav/rfxn.ndb
wget http://www.rfxn.com/downloads/rfxn.hdb -O/var/lib/clamav/rfxn.hdb

/etc/init.d/clamd restart
chkconfig clamd on
```
