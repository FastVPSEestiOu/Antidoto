### Диагностический режим работы

Он используется как замена таких утилит как netstat, ss, lsof, ps, top и другие.

В чем его отличие от существующих пакетов? В первую очередь - концентрация на той информации, которая полезна для выявления зловредного ПО - владельце процессов, папках запуска, сетевых соединениях, прослушиваемых сокетах.

В чем преимущества:
* Удобная работа на серверах с десятками тысяч процессов
* Удобная обработка процессов с форк-архитектурой - отображается только 1 процесс из группы
* Очень высокая скорость работы
* Отсутствие зависимостей на бинарные программы - возможность использования даже на очень поврежденных серверах
* Большие возможности по сокрытию не нужных для анализа проблем процессов/соединений

Как выглядит диагностика типвого сервера в стандартном режиме запуска?
```bash
Pid 12830 is clone
pid: 1 name: init ppid: 0 uid: 0 gid: 0
exe path: /sbin/init
cwd: /
cmdline: init [3]       

file: /dev/initctl


pid: 8513 name: sshd ppid: 1 uid: 0 gid: 0
exe path: /usr/sbin/sshd
cwd: /
cmdline: sshd: root@pts/0  

type: tcp local: xx.xx.xx.xx:22 remote: xx.xx.xx.xx:50997 state: TCP_ESTABLISHED


pid: 518 name: syslogd ppid: 1 uid: 0 gid: 0
exe path: /sbin/syslogd
cwd: /
cmdline: syslogd -m 0 

file: /var/log/messages
file: /var/log/secure
file: /var/log/maillog
file: /var/log/cron
file: /var/log/spooler
file: /var/log/boot.log


pid: 600 name: sendmail ppid: 1 uid: 0 gid: -1
exe path: /usr/sbin/sendmail.sendmail
cwd: /var/spool/mqueue
cmdline: sendmail: accepting connections

file: /var/run/sendmail.pid
type: tcp listen on 127.0.0.1:25


pid: 6063 name: atop ppid: 1 uid: 0 gid: 0
exe path: /usr/bin/atop
cwd: /root
cmdline: /usr/bin/atop -a -w /var/log/atop/atop_20140507 600 

file: /var/log/atop/atop.log
file: /var/log/atop/atop.log
file: /var/log/atop/atop_20140507


pid: 12820 name: httpd ppid: 1 uid: 0 gid: 0
exe path: /usr/sbin/httpd
cwd: /
cmdline: /usr/sbin/httpd 

file: /var/log/httpd/error_log
file: /var/log/httpd/error_log
file: /var/log/httpd/access_log
type: tcp listen on 0:0:0:0:0:0:0:0:80


pid: 9031 name: sshd ppid: 1 uid: 0 gid: 0
exe path: /usr/sbin/sshd
cwd: /
cmdline: /usr/sbin/sshd 

type: tcp listen on 0:0:0:0:0:0:0:0:22
type: tcp listen on 0.0.0.0:22


pid: 109 name: udevd ppid: 1 uid: 0 gid: 0
exe path: /sbin/udevd
cwd: /
cmdline: /sbin/udevd -d 



pid: 608 name: sendmail ppid: 1 uid: 51 gid: 51
exe path: /usr/sbin/sendmail.sendmail
cwd: /var/spool/clientmqueue
cmdline: sendmail: Queue runner@01:00:00 for /var/spool/clientmqueue

file: /var/run/sm-client.pid



pid: 634 name: crond ppid: 1 uid: 0 gid: 0
exe path: /usr/sbin/crond
cwd: /var/spool
cmdline: crond 

file: /var/run/crond.pid


pid: 8516 name: bash ppid: 8513 uid: 0 gid: 0
exe path: /bin/bash
cwd: /root/Antidoto
cmdline: -bash 



pid: 12822 name: httpd ppid: 12820 uid: 48 gid: 48
exe path: /usr/sbin/httpd
cwd: /
cmdline: /usr/sbin/httpd 

file: /var/log/httpd/error_log
file: /var/log/httpd/error_log
file: /var/log/httpd/access_log
type: tcp listen on 0:0:0:0:0:0:0:0:80
```

### Какие возможности есть по фильтрации процессов? 
 
```bash
compress_forks           => 1,    # отображаем процессы с идентичными параметрами как один
show_process_information => 1,    # отображать информацию о процессах
show_tcp => 1,                    # отображать все, связанное с tcp
show_udp => 1,                    # отображать все, связанное с udp
show_whitelisted_listen_tcp => 1, # отображать прослушиваемые сокеты, даже если они в белом списке 
show_whitelisted_listen_udp => 1, # отображать прослушиваемые сокеты, даже если они в белом списке 
show_listen_tcp => 1,             # отображать слушающие tcp сокеты
show_listen_udp => 1,             # отображать слушающие udp сокеты
show_client_tcp => 1,             # отображать клиентские tcp сокеты
show_client_udp => 1,             # отображать клиентские udp сокеты
show_local_tcp_connections => 1,  # отображать локальные tcp соединения 
show_local_udp_connections => 1,  # отображать локлаьные udp соединения
show_open_files => 1 ,            # отображать открытые файлы всех приложений
```
