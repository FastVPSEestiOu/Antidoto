Antidoto
========

Brand new Linux antimalware and antirootkit tool! We know new malware :)

What is Antidoto? It's diagnostic tool for heuristic analysys of Linux machines for detecting malware, viruses and botnets.

How to run:
```bash
wget --no-check-certificate https://raw.githubusercontent.com/pavel-odintsov/Antidoto/master/Antidoto.pl -OAntidoto.pl
wget --no-check-certificate https://raw.githubusercontent.com/pavel-odintsov/Antidoto/master/Antidoto.pm -OAntidoto.pm
perl Antidoto.pl
```
If you work from non-root user you should run it with sudo:
```bash
sudo perl Antidoto.pl
```

If you want to use only linux_network_activity_tracker do following:
```bash
wget --no-check-certificate https://raw.githubusercontent.com/pavel-odintsov/Antidoto/master/Antidoto.pm -OAntidoto.pm
wget --no-check-certificate https://raw.githubusercontent.com/pavel-odintsov/Antidoto/master/linux_network_activity_tracker.pl -Olinux_network_activity_tracker.pl
perl linux_network_activity_tracker.pl
```

Where Antidoto can work?

* Can work either on OpenVZ VPS and Hardware Node
* CentOS 5, CentOS 6
* Debian 5, Debian 6, Debian 7
* Ubuntu 10.xx, 12.xx, 13.xx, 14.xx
* Almost any Linux distro because script written in cross platform language (Perl)

Why Antidoto is more effective than classic antivirus scanners for detecting new malware?
[Test results, sorry it's availible only in russian](https://github.com/pavel-odintsov/Antidoto/wiki/%D0%AD%D1%84%D1%84%D0%B5%D0%BA%D1%82%D0%B8%D0%B2%D0%BD%D0%BE%D1%81%D1%82%D1%8C-%D1%80%D0%B0%D0%B1%D0%BE%D1%82%D1%8B-%D0%B0%D0%BD%D1%82%D0%B8%D0%B2%D0%B8%D1%80%D1%83%D1%81%D0%BE%D0%B2-%D0%BD%D0%B0-%D0%BF%D0%BB%D0%B0%D1%82%D1%84%D0%BE%D1%80%D0%BC%D0%B5-Linux)

What can Antidoto?

* Notify about absent files with last login information (/var/log/btmp, /var/log/wtmp)
* Notify about non blank crontab files for apache and www-data users (/var/spool/cron/crontabs, /var/spool/cron)
* Notify about non blank files and folders with strange names (spaces, dots) in publiс writable folders (/tmp, /var/tmp) 
* Notify about processes launched from current directory (./programm_name) from non root user
* Notify about proceses with absent executable file (which rempved after programm launch)
* Detect very popular malware using direct md5 executable file hashing in memory
* Notify about danger udp and tcp ports listening by software (irc, proxy, botnet controllers)
* Notify about tcp and udp  connections to danger remote ports (irc, botnet controllers)
* Notify about processes with architecture different from the server (for example: 32 bit software running on 64 bit host)
* Notify about processes with statically linked executable files (with integrated libs)
* Notify about processes which was launched with using LD_PRELOAD 
* Notify about processes with executable files with SUID, SGID bits
* Notify about connections to remote servers with abnormal number if threads (5 or more per process)

Antidoto also has audit mode, which works like netstat + lsof + ss and ps, you can read more [here](https://github.com/pavel-odintsov/Antidoto/blob/master/AUDIT.md).

If you know Perl and want to develop new features for Antidoto, please read [developer manual](https://github.com/pavel-odintsov/Antidoto/blob/master/DEVELOPERS.md)

What system requirements of Antidoto?
* Perl interpreter with standard modules
* Standard system tools: cat, file, md5sum
* For working on OpenVZ HWN you need vzlist tool
* For using optional ClamAV scanning mode you should install clamdscan

How to enable ClamAV checks: 
```bash
yum install -y clamav clamd
freshclam
wget http://www.rfxn.com/downloads/rfxn.ndb -O/var/lib/clamav/rfxn.ndb
wget http://www.rfxn.com/downloads/rfxn.hdb -O/var/lib/clamav/rfxn.hdb

/etc/init.d/clamd restart
chkconfig clamd on
```

* Do you have any analogues? [Yes](https://github.com/pavel-odintsov/Antidoto/wiki/%D0%90%D0%BD%D0%B0%D0%BB%D0%BE%D0%B3%D0%B8)
* What reason of creating new software instead improving existing? [Justification](https://github.com/pavel-odintsov/Antidoto/wiki/%D0%9F%D1%80%D0%B8%D1%87%D0%B8%D0%BD%D1%8B-%D1%81%D0%BE%D0%B7%D0%B4%D0%B0%D0%BD%D0%B8%D1%8F-Antidoto)
* What malware types was analzed for creating Antodoto ruleset? [List of analyzed malware](https://github.com/pavel-odintsov/Antidoto/wiki/%D0%9E%D1%81%D0%BD%D0%BE%D0%B2%D0%BD%D1%8B%D0%B5-%D1%82%D0%B8%D0%BF%D1%8B-%D0%B7%D0%BB%D0%BE%D0%B2%D1%80%D0%B5%D0%B4%D0%BD%D0%BE%D0%B3%D0%BE-%D0%9F%D0%9E-%D0%BD%D0%B0-Linux-%D1%81%D0%B5%D1%80%D0%B2%D0%B5%D1%80%D0%B0%D1%85)
