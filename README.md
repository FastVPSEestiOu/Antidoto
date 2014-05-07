Antidoto
========

Linux antimalware and antirootkit tool

Hot to run it:
```bash
wget --no-check-certificate https://raw.githubusercontent.com/pavel-odintsov/Antidoto/master/Antidoto.pl -OAntidoto.pl
perl Antidoto.pl
```
Где работает Antidoto?

* Умеет работать как со стороны OpenVZ ноды для сканирования VPS, так и внутри VPS либо обычного выделенного сервера
* CentOS 5, CentOS 6
* Debian 5, Debian 6, Debian 7
* Ubuntu 10.xx, 12.xx, 13.xx, 14.xx

Что умеет Antidoto?

* Сообщать об удаленных файлах с информацией о дате последнего логина: /var/log/btmp, /var/log/wtmp
* Сообщать о наличии crontab файлов (/var/spool/cron/crontabs, /var/spool/cron) для пользователей apache, www-data
* Сообщать о не пустых файлах и папках со странными именами в папках /tmp и /var/tmp
* Сообщать о процессах запущенных по относительному пути (./programm_name) не от root пользователя
* Сообщать о процессах, исполняемый файл которых был удален после запуска приложения
* Определять особо популярную у нас заразу по md5 (база в 10 вирусов вшита в код)
* Cообщать об опасных прослушиваемых udp, tcp портах (irc, proxy, botnet controllers)
* Cообщать об опасных udp, tcp подключениях к удаленным машинам (irc, botnet controllers)
* Cообщать о процессах с архитектурой отличной от архитектуры машины - например, 32 битное ПО на 64 битном серверве
* Сообщать о процессах, исполняемые файлы которых являются статически слинкованными файлами (с интегрированными библиотеками)
* Сообщать о процессах, которые были запущены с использованием директивы LD_PRELOAD (подключение библиотек к ПО без линковки)
* Сообщать о процессах, бинарные файлы которых имеют флаги SGID или SUID
* Уведомлять о клиентских соединениях на удаленные сервера в более чем 5 потоков на 1 процесс на 1 удаленный порт

Если Antidoto не умеет того, что Вам нужно - вы можете дописать это самостоятельно, документация в файле https://github.com/pavel-odintsov/Antidoto/blob/master/DEVELOPERS.md

Какие системные требования у скрипта?
* Наличие Perl интерпретатора, никаких специализированных модулей не требуется
* Наличие системных утилит: cat, file, md5sum
* Для работы на физической ноде OpenVZ потребуется: vzlist
* При использовании опциаонального режима сканирования всех exe файлов антивирусом ClamAV потребуется: clamdscan 

How to enable ClamAV checks: 
```bash
yum install -y clamav clamd
freshclam
wget http://www.rfxn.com/downloads/rfxn.ndb -O/var/lib/clamav/rfxn.ndb
wget http://www.rfxn.com/downloads/rfxn.hdb -O/var/lib/clamav/rfxn.hdb

/etc/init.d/clamd restart
chkconfig clamd on
```

Какие аналоги данного ПО существуют? https://github.com/pavel-odintsov/Antidoto/wiki/%D0%90%D0%BD%D0%B0%D0%BB%D0%BE%D0%B3%D0%B8
