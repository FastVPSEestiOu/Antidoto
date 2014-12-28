#!/usr/bin/perl

use strict;
use warnings;

use Digest::MD5 qw(md5_hex);
use Data::Dumper;

use Antidoto;

# yum install -y perl-Tree-Simple
#use Tree::Simple;

# Для доступа к переменным: S_ISUID и S_ISGID
use Fcntl ":mode";

# Эту функцию стоит параметризировать в будущем через командную строку
my $audit_params = {
    compress_forks           => 1,    # отображаем процессы с идентичными параметрами как один
    show_process_information => 1,    # отображать информацию о процессах
    show_tcp => 1,                    # отображаться все связанное с tcp
    show_udp => 1,                    # отображаться все связанное с udp
    show_whitelisted_listen_tcp => 1, # отображать прослушиваемые сокеты даже если они в белом списке 
    show_whitelisted_listen_udp => 1, # отображать прослушиваемые сокеты даже если они в белом списке 
    show_listen_tcp => 1,             # отображать слушающие tcp сокеты
    show_listen_udp => 1,             # отображать слушающие udp сокеты
    show_client_tcp => 1,             # отображать клиентские tcp сокеты
    show_client_udp => 1,             # отображать клиентские udp сокеты
    show_local_tcp_connections => 1,  # отображать локальные tcp соединения 
    show_local_udp_connections => 1,  # отображать локлаьные udp соединения
    show_open_files => 1 ,            # отображать открытые файлы всех приложений
};  

# Также добавить белый список прослушиваемых портов и врубать анализ по нему в особо суровых случаях
my $blacklist_listen_ports = {
    1080  => 'socks proxy',
    3128  => 'http proxy',
    6666  => 'irc',
    6667  => 'irc alternative',
    9050  => 'tor',
    # botnet melinda & bill gates https://github.com/ValdikSS/billgates-botnet-tracker/blob/master/gates/gates.py
    36008 => 'botnet melinda & bill gates',
};

my $whitelist_listen_udp_ports = {
    53    => 1,   # dns
    111   => 1,   # portmap
    123   => 1,   # ntp
    137   => 1,   # nmbd
    138   => 1,   # nmdb
    11211 => 1,   # memcached 
};

my $whitelist_listen_tcp_ports = {
    21    => 1, # ftp
    22    => 1, # ssh
    25    => 1, # smtp
    53    => 1, # dns
    80    => 1, # http
    110   => 1, # pop3
    143   => 1, # imap
    443   => 1, # https
    465   => 1, # smtps, secure smtp
    587   => 1, # smtp submission
    993   => 1, # imaps, secure imap 
    995   => 1, # pops, secure pop
    1500  => 1, # ispmanager ihttpd
    3306  => 1, # mysql
    8080  => 1, # apache backend. ispmanager config
    8888  => 1, # fastpanel https
    11211 => 1, # memcached
    10050 => 1, # zabbix agentd
};

my $binary_which_can_be_suid = {
    # Набор ПО от ISPSystems очень беспокоится о своих правах и любит SUID
    '/usr/local/ispmgr/bin/billmgr'  => 1,
    '/usr/local/ispmgr/bin/ispmgr'   => 1,
    '/usr/local/ispmgr/bin/vdsmgr'   => 1,
    '/usr/local/ispmgr/sbin/pbackup' => 1,

    '/usr/bin/mtr' => 1, # mtr, debian
    '/usr/sbin/postdrop' => 1,
    '/usr/sbin/exim4' => 1,
    '/usr/sbin/exim' => 1, # Centos exim
    '/bin/su' => 1,
    '/usr/bin/su' => 1,
    '/usr/lib/sm.bin/sendmail' => 1,
    '/usr/sbin/sendmail.sendmail' => 1,
    '/usr/bin/screen' => 1,
    '/usr/bin/sudo' => 1,
    '/usr/bin/ssh-agent' => 1,
    '/usr/bin/fping' => 1,
    '/bin/mount' => 1,
    '/bin/ping' => 1,
    '/usr/local/ispmgr/cgi/download' => 1,
};

# Паттерны найденных вирусов
my $virus_patterns = {
    '21f9a5ee8af73d2156333a654130f3f8' => 1, # ps_virus_ct_6205
    'a6752df85f35e6adcfa724eb5e15f6d0' => 1, # virus_from_43165
    '99ca61919f5afbdb3c0e07c30fad5bb1' => 1, # named bitcoin miner
    '36c97cdd3caccbacb37708e84b22a627' => 1, # jawa, порутана машина
    '36f6c1169433cc8a78498d54393132ed' => 1, # atd демон
    'f9ad37bc11a4f5249b660cacadd14ad3' => 1, # sfewfesfs/pojie:  Melinda & Bill gates malware
    '9b6283e656f276c15f14b5f2532d24d2' => 1, # sfewfesfsh: Melinda & Bill gates malware
    'd7cb8d530dd813f34bdcf1b6c485589b' => 1, # irc_bouncer_hidden_as_ssh_from_5560
};

# Список "хороших" открытых файлов, на которые не стоит даже реагировать
my $good_opened_files = { 
    '/dev/null'    => 1,
    '/dev/urandom' => 1,
    '/dev/random'  => 1,
    '/dev/stdin'   => 1,
    '/dev/ptmx'    => 1,
    '/dev/pts/1'   => 1,
    '/dev/pts/0'   => 1,
    '/dev/console' => 1,
};

# cwd, которые не стоит считать подозрительными
my $good_cwd = { 
    '/var/run' => 1,
    '/run/dovecot' => 1,
    '/opt/php5/bin' => 1,
    '/var/lib/mysql' => 1,
    '/run/saslauthd' => 1,
    '/var/spool/cron' => 1,
    '/var/run/dovecot' => 1,
    '/var/run/saslauthd' => 1,
    '/var/www/admin/php-bin' => 1,
    '/var/run/dovecot/login' => 1,
    '/var/spool/postfix' => 1,
    '/usr/local/ispmgr' => 1,
    '/var/spool/mqueue' => 1,
    '/usr/local/fastpanel/daemon' => 1,
    '/run/dovecot/empty' => 1,
    '/' => 1,
    '/var/spool/clientmqueue' => 1,
    '/var/spool/cron/atjobs' => 1,
};


 
# Хэш куда мы поместим карту: хэш - путь до бинарного файла

# Тут явно забиты бинарные файлы, которые распространяются вне пакетных менеджеров
my $hash_lookup_for_all_binary_files = {
    # TODO: эти хэши забиты в порядке ОТЛАДКИ, это могут быть и протрояненые ispmgr!
    # Найти способ узнать их чек суммы
    'b9fa02373babd17406ed70eb943b8d31' => '/usr/local/ispmgr/sbin/ihttpd',
    'a60730a0026a34188f3e203f7c572bb5' => '/usr/local/ispmgr/bin/ispmgr',
    'b5eb4b504e6588ba237998dbac670a59' => '/usr/local/ispmgr/bin/ispmgr',
    '1717a4987853e5e774b6ec6b0b0c448d' => '/usr/local/ispmgr/bin/ispmgr',
    '9fbf9a6f9b24e5ca2b31b5990824a6ff' => '/usr/local/ispmgr/bin/ispmgr',
    'e62c0a2a25eeb622c1320db8f5d9039d' => '/usr/local/ispmgr/bin/ispmgr',
    '90899219b3e75b9d3064260c25270650' => '/usr/local/ispmgr/bin/ispmgr',

    # А это Коля забил неверные чексуммы, issue уже передан в работу
    '7241fcc1ce18d52e70810b65625bd61d' => '/opt/php5/bin/php',
    '5008e5e31d2f7efe5516f280fd13681b' => '/opt/php5/bin/php',
    '2c0144f5d550fa106081d1eaacbb033d' => '/opt/php5/bin/php',
    'ed523eea1d33332acb38e620656c042a' => '/opt/php5/bin/php-cgi',
    'ba05b2f694c61a314846a42801694dfe' => '/opt/php5/bin/php-cgi',
    'e4ef72a1c092944dcf2886feeb581469' => '/opt/php5/bin/php-cgi',
   
    #  /sbin/syslogd не имеет в пакете чексумм
    '21a265738651407ce0fcede295abd675' => '/sbin/syslogd',
    'e98f49146b5e8203838a2d451835eb1a' => '/sbin/syslogd',
    '58ae7c68e945f1d88b6fc0c46494812b' => '/sbin/syslogd',

    # vzapi tools
    'd77fb76bcddb774a8a541dce42667b5d' => '/usr/bin/md5_pipe',
};


# режима аудита, когда мы печатаем всю возможную извлеченную информацию о процессах
my $audit_mode = '';

my $execute_full_hash_validation = 0;

my $is_openvz_node = '';

# Проверяем окружение, на котором мы работаем
if (-e "/proc/user_beancounters" && -e "/proc/vz/fairsched") {
    $is_openvz_node = 1; 
}

my @running_containers = ();

# Если мы работем на OpenVZ ноде, то есть возможность передать для сканирования лишь конкретный контейнер
if ($is_openvz_node) {
    
    # Если нам передали параметры командной строки, то сканируем переданный параметром контейнер
    if (scalar @ARGV > 0 && $ARGV[0] =~ /^\d+$/) {
        @running_containers = @ARGV;
    } else {
        @running_containers = get_running_containers_list();
    }

}

if (scalar @ARGV > 0 && $ARGV[0] =~ /^\-\-audit$/) {
    $audit_mode = 1;
}

# Список системных пользователей, которые в нормальных условиях не должны иметь свой crontab в /var/spool/cron/crontabs
my $users_which_cant_have_crontab = { 
    'www-data' => 1,
    'apache'   => 1,
};


# Проверка конетейнера на предмет не порутали ли его
my $global_check_functions = {
    check_absent_login_information => \&check_absent_login_information,
    check_user_crontabs => \&check_user_crontabs,
    check_dirs_with_whitespaces => \&check_dirs_with_whitespaces,
};   

# Проверки для процессов
my $process_checks = {
    check_cmdline => \&check_cmdline,
    check_for_deleted_exe => \&check_for_deleted_exe,
    check_exe_files_by_checksumm => \&check_exe_files_by_checksumm,
    check_process_open_fd => \&check_process_open_fd,
    check_32bit_software_on_64_bit_server => \&check_32bit_software_on_64_bit_server,
    check_ld_preload => \&check_ld_preload,
    check_suid_exe => \&check_suid_exe,
    check_process_parents => \&check_process_parents,
    # check_binary_with_clamd => \&check_binary_with_clamd,
    # check_changed_proc_name => \&check_changed_proc_name,
    # check_cwd => \&check_cwd,
};

# TODO: реализовать
# Правила, описывающие поведение процессов
my $processes_rules = {
    'apache_debian' => {
        'uid'         => 33,
        'gid'         => 33,
        'exe'         => "/usr/lib/apache2/mpm-prefork/apache2",
        'name'        => "apache2",
        'can_listen'  => [ '80', '81', '8080', '443' ],
    }
};


# TODO: сделать этот валидатор не локальным
# Для отдельного сервера вполне посильная задача собрать ключевые суммы
#    $execute_full_hash_validation = 1; 

process_standard_linux_server();

# В случае OpenVZ ноды мы обходим все контейнеры
CONTAINERS_LOOP:
for my $container (@running_containers) {
    if ($container eq '1' or $container eq '50') {
        # Skip PCS special containers
        next;
    }


    my @ct_processes_pids = read_file_contents_to_list("/proc/vz/fairsched/$container/tasks");

    # Тут мы читаем псевдо-файла /proc/CT_INIT_PID/net/*, так как там содержатся все соединения для данного контейнера,
    # а вовсе не соединения для данного процесса

    # TODO: ВЫПИЛИТЬ дублированное получение pid
    my $container_init_process_pid_on_node = get_init_pid_for_container(\@ct_processes_pids);

    my $connections = read_all_namespace_connections($container_init_process_pid_on_node);
    my $inode_to_socket = build_inode_to_socket_lookup_table($connections);

    # Собираем хэш всех бинарных файлов контейнера для последующей валидации
    if ($execute_full_hash_validation) {
        $hash_lookup_for_all_binary_files = {};
        #### build_hash_for_all_binarys($container);
    }

    for my $check_function_name ( keys %$global_check_functions ) {
        #print "We call function $check_function_name for $container\n";
        my $sub_ref = $global_check_functions->{$check_function_name};
        $sub_ref->($container);
    }
   
    check_orphan_connections($container, $inode_to_socket);

    my $server_processes_pids = get_server_processes_detailed( { inode_to_socket => $inode_to_socket, ctid => $container } );

    if ($audit_mode) {
        print "We see on container $container\n";
        build_process_tree($server_processes_pids);
        # skip checks
        next CONTAINERS_LOOP;
    }  

    PROCESSES_LOOP:
    for my $pid (keys %$server_processes_pids) {
        my $status = $server_processes_pids->{$pid};

        call_process_checks($pid, $status); 
    }

}

# Запускаем все проверки для контейнера
sub call_process_checks {
    my ($pid, $status, $inode_to_socket) = @_;

    # Вызываем последовательно все указанные функции для каждого процесса
    for my $check_function_name ( keys %$process_checks ) {
        # Если процесс перестал существовать во время проверки, то, увы, мы переходим к следующему
        unless (-e "/proc/$pid") {
            return "";
        }

        #print "We call function $check_function_name for process $pid\n";
        my $sub_ref = $process_checks->{$check_function_name};
        $sub_ref->($pid, $status, $inode_to_socket);
    }
}


# Обработка обычного сервера
sub process_standard_linux_server {
    my $connections     = read_all_namespace_connections();
    my $inode_to_socket = build_inode_to_socket_lookup_table($connections);

    # Собираем хэш всех бинарных файлов контейнера для последующей валидации
    if ($execute_full_hash_validation) {
         #build_hash_for_all_binarys('');
    }

    for my $check_function_name ( keys %$global_check_functions ) {
        #print "We call function $check_function_name for $container\n";
        my $sub_ref = $global_check_functions->{$check_function_name};
        $sub_ref->();
    }

    check_orphan_connections(0, $inode_to_socket);

    # В этом подходе есть еще большая проблема, дублирование inode внутри контейнеров нету, но
    # есть куча "потерянных" соединений, у которых владелец inode = 0, с ними нужно что-то делать

    # То, что мы запрашиваем CTID 0 означает, что в случае если это OpenVZ мы получим все процессы CT 0, то есть аппаратной ноды
    # а если работаме на железе без виртулизации и прочего - получим просто список процессов
    my $server_processes_pids = get_server_processes_detailed( { inode_to_socket => $inode_to_socket, ctid => 0 } );
    
    if ($audit_mode) {
        build_process_tree($server_processes_pids);
        # skip other checks
        return;
    }

    PROCESSES_LOOP:
    for my $pid (keys %$server_processes_pids) {
        my $status = $server_processes_pids->{$pid};
    
        call_process_checks($pid, $status, $inode_to_socket);
    }
}


# Если у процесса есть множество дочерних форков с аналогичным набором параметров и дескрипторов, то исключаем их из рассмотрения вообще
sub filter_multiple_forks {
    my ($server_processes_pids, $sorted_pids) = @_; 

    my @result = ();

    my $prev_item = '';
    # Уникализация процессов, какой смысл рассматривать 50 форков апача как отдельные?
    PID_LOOP:
    for my $pid (@$sorted_pids) {
        my $status = $server_processes_pids->{$pid};

        # В первый запуск просто положим туда следующий 
        if ($prev_item) {
            if (compare_two_hashes_by_list_of_fields($status, $prev_item,
                ('PPid', 'fast_exe', 'Name', 'fast_uid', 'fast_gid', 'fast_fds_checksumm') ) ) {
                # Если это клон предыдущего процесса, то просто скачем на следующую итерацию и тем самым исключаем его из обработки 
                # print "Pid $pid $status->{Name} is clone\n";
                next PID_LOOP;
            }  
        }    

        push @result, $pid;
        $prev_item = $status;
    } 

    return @result;
}

# Главная рабочая функция режима audit, отображаем всю возможную информацию по процессу
sub build_process_tree {
    my $server_processes_pids = shift;

    # Вершина дерева - нулевой pid, это ядро
    #my $tree = Tree::Simple->new("0", Tree::Simple->ROOT);

    # Сортировка по PID родительского процесса кажется мне самой логичной
    my @sorted_pids = sort {
        $server_processes_pids->{$a}->{PPid} <=>
        $server_processes_pids->{$b}->{PPid}
    } keys %$server_processes_pids;

    if ($audit_params->{compress_forks}) { 
        @sorted_pids = filter_multiple_forks($server_processes_pids, [@sorted_pids]);
    }

    for my $pid (@sorted_pids) {
        my $status = $server_processes_pids->{$pid};

        my @sorted_fds = sort { $a->{type} cmp $b->{type} } @{ $status->{fast_fds} };

        if ($audit_params->{show_process_information}) {
            print get_printable_process_status($pid, $status) . "\n";

            if (scalar @sorted_fds > 0) { 
                print "\n";
            }     
        }

        # Сортируем по типу перед отображением
        FDS_LOOP: 
        for my $fd (@sorted_fds) {
            if ($fd->{type} eq 'tcp') {
                if ($audit_params->{show_tcp}) {
                    if (is_listen_connection($fd->{connection}) ) {
                        my $it_is_whitelisted_connection = $whitelist_listen_tcp_ports->{ $fd->{connection}->{local_port} };
                        
                        if ($audit_params->{show_listen_tcp}) {
                            my $show = 1;
        
                            # Мы попали на соединение в белом списке
                            # И если его отображение запрещено, то скрываем
                            if ($it_is_whitelisted_connection && ! $audit_params->{show_whitelisted_listen_tcp}) {
                                $show = 0;
                            }

                            if ($show) {
                                print connection_pretty_print($fd->{connection}) . "\n";
                            }
                        }
                    } else {
                        print connection_pretty_print($fd->{connection}) . "\n" if $audit_params->{show_client_tcp};
                    } 
                }
            } elsif ($fd->{type} eq 'udp') {
                if ($audit_params->{show_udp}) {
                    if (is_listen_connection($fd->{connection}) ) {
                        my $it_is_whitelisted_connection = $whitelist_listen_udp_ports->{ $fd->{connection}->{local_port} };

                        if ($audit_params->{show_listen_udp}) {
                            my $show = 1;

                            # Мы попали на соединение в белом списке
                            # И если его отображение запрещено, то скрываем
                            if ($it_is_whitelisted_connection && ! $audit_params->{show_whitelisted_listen_udp}) {
                                $show = 0; 
                            }    
    
                            if ($show) {
                                print connection_pretty_print($fd->{connection}) . "\n";
                            }
                        }
                    } else {
                        print connection_pretty_print($fd->{connection}) . "\n" if $audit_params->{show_client_udp};
                    }
                }
            } elsif ($fd->{type} eq 'file') {
                unless( $good_opened_files->{ $fd->{path} } ) {
                    if ($audit_params->{show_open_files}) {
                        print "file: $fd->{path}\n";
                    }
                }
            } else {
                # another connections
            }
        }

        if ($audit_params->{show_process_information}) {
            print "\n\n";
        }
    }
}



# Получить список процессов забитый информацией о них
sub get_server_processes_detailed {
    my $params = shift;

    my $ctid = $params->{ctid};
    my $inode_to_socket = $params->{inode_to_socket};
    
    my $processes = {};

    my $is_openvz_node = '';
    if (-e "/proc/user_beancounters" && -e "/proc/vz/fairsched") {
        $is_openvz_node = '1';
    }

    my @process_pids = ();
   
    my $init_process_pid = 1; 
    if ($is_openvz_node) {
        # Да, для OpenVZ это очень удобный способ получения содержимого ноды
        @process_pids = read_file_contents_to_list("/proc/vz/fairsched/$ctid/tasks");
    } else {
        @process_pids = get_server_processes();
    }

    my $passwd_data = '';
    if ($is_openvz_node) {
        if ($ctid == 0 ) {
            $init_process_pid = 1; 
            $passwd_data = parse_passwd_file("/etc/passwd");
        } else {
            $init_process_pid  = get_init_pid_for_container(\@process_pids);
            $passwd_data = parse_passwd_file("/vz/root/$ctid/etc/passwd");
        }    
    } else {
        $init_process_pid = 1;
        $passwd_data = parse_passwd_file("/etc/passwd");
    }

    my @container_ips = ();
    if ($ctid > 0) {
        @container_ips = get_ips_for_container($ctid);
    }

    my $it_is_openvz_container = -e "/proc/user_beancounters";

    my $init_elf_info = `cat /proc/$init_process_pid/exe | file -`;
    chomp $init_elf_info;

    my $server_architecture = get_architecture_by_file_info_output($init_elf_info);

    PROCESSES_LOOP:
    for my $pid (@process_pids) {
        my $status = get_proc_status($pid);

        unless ($status) {
            next;
        }

        $status = process_status($pid, $status, $inode_to_socket);

        # Таким хитрым образом мы можем скрывать системные процессы ядра
        unless (defined($status->{fast_cmdline})) {
            next;
        }

        # В случае, если со стороны ноды имеется vzctl, который инжектирован в пространство контейнера,
        # то его exe файлы и прочее прочесть нельзя - исключаем его из рассмотрения
        # stat /proc/14865/exe
        # File: `/proc/14865/exe'stat: cannot read symbolic link `/proc/14865/exe': Permission denied
        if ($it_is_openvz_container && $status->{Name} eq 'vzctl') {
            my @stat_data = stat "/proc/$pid/exe";

            if (scalar @stat_data == 0 && $! eq 'Permission denied') {
                # Исключаем его как процесс с ноды
                next PROCESSES_LOOP;
            }
            # И если при stat мы получаем ошибку доступа, то это правда vzctl с ноды
        }
        
        # Получаем информацию о соотвествии имен и uid пользователей 
        $status->{fast_passwd} = $passwd_data;

        # Добавляем параметр "архитектура хост контейнера"
        $status->{fast_container_architecture} = $server_architecture;

        # Добавляем псевдо параметр - local_ips, это локальные IP контейнера
        $status->{fast_local_ips} = [ @container_ips ];

        $processes->{$pid} = $status;
    }

    return $processes;
}



# Обработать статус процесса, добавив в него ряд полезных пунктов
sub process_status {
    my $pid = shift;
    my $status = shift;
    my $inode_to_socket = shift;

    # В случае, если все Uid/Gid у нас совпадают
    $status->{fast_uid} = get_process_uid_or_gid('Uid', $status);
    $status->{fast_gid} = get_process_uid_or_gid('Gid', $status);

    # также добавляем в статус фейковые параметры: exe/cwd, так как они нам многократно пригодятся
    my $cwd_path = "/proc/$pid/cwd";
    my $exe_path = "/proc/$pid/exe";

    $status->{fast_cwd} = readlink($cwd_path);
    $status->{fast_exe} = readlink($exe_path);

    unless (defined($status->{fast_cwd})) {
        $status->{fast_cwd} = '';
    }    

    unless (defined($status->{fast_exe})) {
        $status->{fast_exe} = '';
    }    


    # в exe может быть еще вот такое чудо:  ' (deleted)/opt/php5/bin/php-cgi'

    # Для кучи контейнеров cwd прописан вот так /vz/root/54484 то есть с уровня ноды, а нам это не нужно,
    # Для не openvz машин никаких последствий такое не несет
    if ($status->{fast_cwd}) {
        $status->{fast_cwd} =~ s#/vz/root/\d+/?#/#g;
    }

    if ($status->{fast_exe}) {
        $status->{fast_exe} =~ s#/vz/root/\d+/?#/#g;
    }

    # обрабатываем cmdline
    $status->{fast_cmdline} = read_file_contents("/proc/$pid/cmdline");

    if ($status->{fast_cmdline}) {
        # Но /proc/$pid/cmdline интересен тем, что в нем используются разделители \0 и их нужно разделить на пробелы
        $status->{fast_cmdline} =~ s/\0/ /g;
    }

    # исключаем из рассмотрения системные процессы ядра
    if (defined($status->{fast_cmdline}) && $status->{fast_cmdline}) {
        # обрабатываем environ
        my $environ_data = read_file_contents("/proc/$pid/environ");

        if (defined($environ_data)) {
            $status->{fast_environ} = {};        

            # тут также используются \0 как разделители
            for my $env_elem (split  /\0/, $environ_data) {
                my @env_raw = split '=', $env_elem, 2;

                # Внутри может быть всякая бинарная хренотень, так что что реагируем лишь в случае, если нашли знак =
                if (scalar @env_raw  ==  2) { 
                    $status->{fast_environ}->{$env_raw[0]} = $env_raw[1]; 
                }    
            } 

        }
    }

    # Получаем удобный для обработки список дескрипторов (файлов+сокетов) пороцесса
    $status->{fast_fds} = get_process_connections($pid, $inode_to_socket);

    # В режиме аудита нам часто нужна дедупликация процессов, чтобы не показывать 1000 форков
    if ($audit_mode) {
        $status->{fast_fds_checksumm} = create_structure_hash($status->{fast_fds});
    }

    return $status;
}




# Проверяем на предмет наличия папок с пробельными именами в /tmp
sub check_dirs_with_whitespaces {
    my $ctid = shift;

    my $prefix = '';

    if ($ctid) {
        $prefix = "/vz/root/$ctid";
    }    

    TEMP_FOLDERS_LOOP:
    for my $temp_folder ("$prefix/tmp", "$prefix/var/tmp", "$prefix/dev/shm") {
        unless (-e $temp_folder) {
            next TEMP_FOLDERS_LOOP;
        }

        my @files = list_all_in_dir($temp_folder);

        for my $file (@files) {
            # Хакеры очень любят пробельные имена, три точки или "скрытые" - начинающиеся с точки
            if ($file =~ /^\s+$/ or $file =~ /^\.{3,}$/ or $file =~ /^\./) {
                if (-f "$temp_folder/$file" && get_file_size("$temp_folder/$file") > 0) {
                    if ($ctid) {
                        warn "We found a file with suspicious name $file in CT $ctid in directory: $temp_folder\n";
                    } else {
                        warn "We found a file with suspicious name $file in directory: $temp_folder\n";
                    }
                }

                # Мы реагируем только на НЕ пустые папки
                if (-d "$temp_folder/$file") {
                    my @folder_content = list_all_in_dir("$temp_folder/$file");
                    if (scalar @folder_content > 0 ) {
                        if ($ctid) {
                            warn "We found not empty directory $file (@folder_content) which possibly hidden in directory: $temp_folder in CT $ctid\n";
                        } else {
                            warn "We found not empty directory $file (@folder_content) which possibly hidden in directory: $temp_folder\n";
                        }
                    }
                }
            }
        }
    }
}

# Проверяем на предмет того, что бинарный файл имеет SUID флаг
sub check_suid_exe {
    my ($pid, $status) = @_;

    my $prefix = '';

    if (defined($status->{envID}) && $status->{envID}) {
        $prefix = "/vz/root/$status->{envID}";
    }

    # Если файл не существует или удален, то тупо скипаем эту проверку
    unless (-e "$prefix/$status->{fast_exe}") {
        return;
    }  

    my @stat_data = stat "$prefix/$status->{fast_exe}";

    my $mode = $stat_data[2];

    my $is_suid = $mode & S_ISUID;

    my $is_sgid = $mode & S_ISGID;

    # Convert to bool form
    if ($is_suid) {
        $is_suid = 1;
    }

    if ($is_sgid) {
        $is_sgid = 1;
    }
    
    if ($is_suid or $is_sgid) {
        # Если бинарика нет в списке разрешенных, то, очевидно, стоит о нем упомянуть
        unless ( $binary_which_can_be_suid->{ $status->{fast_exe} } ) {
            print_process_warning($pid, $status, "we found SUID ($is_suid) or SGID bit ($is_sgid) enabled, it's very dangerous");
        }
    }
}

# Печатаем уведомление о подозрительном процессе
sub print_process_warning {
    my $pid  = shift;
    my $status = shift;
    my $text = shift;

    my $container_data = '';
    if (defined($status->{envID}) && $status->{envID}) {
        $container_data = " from CT: $status->{envID}";
    }

    print "We got warning about process" ."$container_data: '$text'\n" . get_printable_process_status($pid, $status) . "\n\n";
}

sub get_printable_process_status {
    my ($pid, $status) = @_;
   
    my $container_data = '';
    if (defined($status->{envID}) && $status->{envID}) {
        $container_data = "CT: $status->{envID}";
    }
 
    return  "pid: $pid name: $status->{Name} ppid: $status->{PPid} uid: $status->{fast_uid} gid: $status->{fast_gid} $container_data\n" .
        "exe path: $status->{fast_exe}\n" .
        "cwd: $status->{fast_cwd}\n" .
        "cmdline: $status->{fast_cmdline}"; 
}

# Проверка истинности процесса - тот ли он, за кого себя выдает 
sub check_process_truth {
    my ($pid, $status) = @_;

    # TODO: должна осуществляться по правилам: $processes_rules
}

# Проверяем родителей процесса и если среди них есть Апач, то стоит этот случай исследовать
sub check_process_parents {
    my ($pid, $status) = @_;

    my $parent_pid = $status->{PPid};

    # Этот процесс запущен сам по себе, он нас не интересует, скорее всего он системный
    if ($parent_pid == 1) {
        return;
    }
    
    # TODO: здесь нужно разместить код эвристической проверки 
}

# Проверка на предмет загрузки того или иного сервиса с LD_PRELOAD
sub check_ld_preload  {
    my ($pid, $status) = @_;   

    my $ld_preload_whitelist = {
        '/usr/lib/authbind/libauthbind.so.1' => 1,       # https://packages.debian.org/wheezy/authbind, его использует tomcat
        '/usr/local/lib/authbind/libauthbind.so.1' => 1, # Bitrix smtpd.php
    };

    if ( defined($status->{fast_environ}) && $status->{fast_environ} ) {
        # Тут бывают вполне легальные использования, например: http://manpages.ubuntu.com/manpages/hardy/man1/authbind.1.html
        # Такой "подход" используется в Bitrix (SIC) environment

        my $ld_preload = $status->{fast_environ}->{'LD_PRELOAD'};
        if (defined($ld_preload) && $ld_preload && !defined ($ld_preload_whitelist->{$ld_preload})) {
            print_process_warning($pid, $status, "This process loaded with LD_PRELOAD ($ld_preload) an it may be a VIRUS");
        }
    }
}

sub check_user_crontabs {
    my $ctid = shift;

    my $prefix = '';

    if ($ctid) {
        $prefix = "/vz/root/$ctid";
    }    

    # debian / centos
    for my $cron_folder ("$prefix/var/spool/cron/crontabs", "$prefix/var/spool/cron") {

        my @crontab_files = list_files_in_dir($cron_folder);

        for my $cron_file (@crontab_files) {
            if ($users_which_cant_have_crontab->{ $cron_file }) {
                my @crontab_file_contents = read_file_contents_to_list("$cron_folder/$cron_file");

                # Фильтруем строки с комментариями
                @crontab_file_contents = grep { if(!/^#/ and length ($_) > 0) {1;} else {0;}} @crontab_file_contents;

                # Отключим реагирование на служебную команду MAILTO
                @crontab_file_contents = grep { !/^(?:MAILTO|PATH)/ } @crontab_file_contents;

                if (scalar @crontab_file_contents > 0) {
                    if ($ctid) {
                        warn "Please check CT $ctid ASAP because it probably has malware in user cron\n";
                    } else {
                        warn "Please check crontab ASAP because it probably has malware in user cron\n";
                    }
                    warn "Cron content for $cron_file: " . ( join ",", @crontab_file_contents ) . "\n" 
                }
            }
        }
    }
}

# Валидатор cmdline, так как почти всегда, если он начинается с ./ то жди проблем
sub check_cmdline { 
    my ($pid, $status) = @_;

    if ($status->{fast_cmdline} && $status->{fast_cmdline} =~ m/^\./) {

        # Тимспики запускают только так, так что уберем ругань на них
        if ($status->{Name} =~ /ts3server_linux/ ) {
            return;
        }

        # Если программа запущена от рута, то уведомлять о таком нет особого смысла, так как пользователи часто так делают да и руткиты могут прописаться в системные пути и не обязательно будут запущены вручную
        unless ($status->{fast_uid} == 0 && $status->{fast_gid} == 0) {
            print_process_warning($pid, $status, "it running manually from NOT root user and it's very dangerous");
        }
    }
}

sub check_exe_files_by_checksumm {
    my ($pid, $status) = @_;

    my $prefix = '';;

    if (defined($status->{envID}) && $status->{envID}) {
        $prefix = "/vz/root/$status->{envID}";
    }

    # рассчитаем md5, оно сработает даже для удаленного файла
    my $md5 = md5_file("/proc/$pid/exe");    

    unless ($md5) {
        warn "Can't calulate md5 for exe from process $pid\n";
        return;
    } 

    # Проверяем, чтобы файл был захэширован корректно
    unless ($status->{fast_hash_lookup_for_all_binary_files}->{$md5}) {
        
        if ($execute_full_hash_validation) {
            if (-e "$prefix/usr/bin/dpkg") {
                print_process_warning($pid, $status, "can't find checksumm ($md5) for this binary file in packages database. Please check it");
            } else {
                # TODO:
                # Это CentOS и как извлечь из него сигнатуры я пока совершенно не понимаю
            }
        }
    }

    if ($virus_patterns->{$md5}) {
        print_process_warning($pid, $status, "it's 100% virus");
    }
}

# Проверка на предмет того, что исполняемый файл приложения удален после запуска
sub check_for_deleted_exe {
    my ($pid, $status) = @_;

    my $prefix = '';;

    if (defined($status->{envID}) && $status->{envID}) {
        $prefix = "/vz/root/$status->{envID}";
    }

    if ($status->{fast_exe} =~ m/deleted/) {
        my $exe_path = $status->{fast_exe};
        
        # TODO: выпилить обходники!
        # Чудеса нашей fastpanel, она не перезапускает свои CGI процессы, баг отрепорчен:
        # Исклчюение для /var/www/admin/php-bin сделано по причине вот такого поведения CGI процессов FastPanel:
        # cwd -> /var/www/admin/php-bin
        # exe ->  (deleted)/tmp/rst16186.000510e0
        if ($status->{fast_exe} =~ m#/opt/php5/bin/php-cgi# or $status->{fast_cwd} =~ m#/var/www/admin/php-bin# ) {
            return;
        }

        # Приведем путь в порядок
        # (deleted)/usr/bin/php5-cgi
        $exe_path =~ s#^\s*\(deleted\)\s*##;
    
        # Debian 6 Squeeze в этом плане выпендривается и пишет deleted в конце:
        # /proc/10187/exe -> /usr/bin/php5 (deleted)
        $exe_path =~ s#\s*\(deleted\)$##;

        # Тут бывают случаи: бинарик удален и приложение оставлено работать либо бинарник заменен, а софт работает со старого бинарика
        # Первое - скорее всего малварь, иначе - обновление софта без обновление либ
        unless (-e "$prefix/$exe_path") {
            print_process_warning($pid, $status, "Executable file for this process was removed, it's looks like malware");
        }
    }
}



# Обойдем все открыте соединения процессов и оценим их состояние
sub check_process_open_fd {
    my ($pid, $status) = @_;

    # Хэш, в котором будет храниться число соединений на удаленный сервер от процесса на определенный порт
    my $connections_to_remote_servers = {};

    # Тут у нас может быть информация о локальных IP
    if ($status->{fast_local_ips}) {

    }

    my $process_connections = $status->{fast_fds};

    #print Dumper($process_connections);

    CONNECTIONS_LOOP:
    for my $connection (@$process_connections) {
        if ($connection->{type} eq 'unknown') {
            # TODO:
            next CONNECTIONS_LOOP;
        } elsif (in_array($connection->{type}, ('udp', 'tcp') ) ) {
            my $connection = $connection->{connection};

            if (is_listen_connection($connection)) {
                # listen  socket

                # Если тот или иной софт забинден на локалхост, то он нас не интересует
                if (is_loopback_address($connection->{local_address})) {
                    next CONNECTIONS_LOOP;
                }    

                if (my $port_description = $blacklist_listen_ports->{ $connection->{local_port} }) {
                    print_process_warning($pid, $status, "process listens DANGER ($port_description) $connection->{socket_type} port $connection->{local_port}");
                }
            } else {
                # Это может быть внутренее соединение, которое не интересно нам при анализе
                if (is_loopback_address($connection->{rem_address})) {
                    next CONNECTIONS_LOOP;
                }

                # Увеличим посчитаем число соединений на удаленные машины с детализацией по портам
                $connections_to_remote_servers->{ $connection->{rem_port} } ++; 

                # client socket
                if (my $port_description = $blacklist_listen_ports->{ $connection->{rem_port} }) {
                    print_process_warning($pid, $status, "process connected to DANGER ($port_description) $connection->{socket_type} port $connection->{rem_port} to the server $connection->{rem_address}");
                }
            }
        }
    }

    for my $remote_port_iteration (scalar keys %$connections_to_remote_servers > 0) {
        my $number_of_connections = $connections_to_remote_servers->{ $remote_port_iteration };

        if (defined($number_of_connections) && $number_of_connections > 5) {    
            print_process_warning($pid, $status, "it has $number_of_connections connections to $remote_port_iteration. Looks like flood bot");
        }
    }      
}


# Если btmp/wtmp удален, то скорее всего машину порутали
sub check_absent_login_information {
    my $ctid = shift;

    my $prefix = '';

    if ($ctid) {
        $prefix = "/vz/root/$ctid";
    }

    # Debian: btmp
    # CentOS: wtmp
    unless (-e "$prefix/var/log/btmp" or -e "$prefix/var/log/wtmp") {
        if ($ctid) {
            warn "CT $ctid is probably rooted because btmp/wtmp file is absent";
        } else {
            warn "Server is probably rooted because btmp/wtmp file is absent";
        }
    }
}

# Тут нужно собрать все файлы открытые на сервере
my $global_opened_files = {};
sub run_clamav {
    open my $fl, ">", "files_to_scan" or die "Can't";
    for(keys %$global_opened_files) {
        #system("maldet -a $_");
        #system("clamscan $_|grep infected -i");
        print {$fl} "$_\n";
    }

    # Call freshclam every startup
    system("clamscan --file-list=files_to_scan --infected -d /usr/local/maldetect/sigs/rfxn.ndb -d /usr/local/maldetect/sigs/rfxn.hdb -d /var/lib/clamav");
}

my $get_debian_package_name_by_path = {
};

sub build_hash_for_all_binarys {
    my $ctid = shift;

    my $hash_lookup_for_all_binary_files = {};

    my $prefix = '';
    if (defined($ctid) && $ctid) {
        $prefix = "/vz/root/$ctid";
    } else {
        $prefix = '';
    }

    # Это дебиян и мы можем выполнить валидацию
    if (-e "$prefix/usr/bin/dpkg") {
        my @files = list_files_in_dir("$prefix/var/lib/dpkg/info");
        # Фильтруем лишь sums файлы
        @files = grep { /\.md5sums$/ } @files;
   
        for my $file (@files) {
            my @file_content = read_file_contents_to_list("$prefix/var/lib/dpkg/info/$file");
            
            for my $line (@file_content) {
                # TODO: улучшить фильтрацию
                # А вот бинарики апача: usr/lib/apache2/mpm-worker/apache2
                # Бинарики пофикса: usr/lib/postfix/qmqpd
                if ($line =~ m#(bin|lib)#) {
                    my @data = split /\s+/, $line, 2;
    
                    $hash_lookup_for_all_binary_files-> { $data[0] } = "/$data[1]";
                }
            }
        } 
    }

    return $hash_lookup_for_all_binary_files;
}



# Проверить бинарный файл антииврусом ClamAV
sub check_binary_with_clamd {
    my ($pid, $status) = @_;

    my $scan_raw_result = `cat /proc/$pid/exe | clamdscan -`;
    chomp $scan_raw_result;

    my $scan_result = '';

    if ($scan_raw_result =~ m/stream: (.+)$/im) {
        $scan_result = $1;
    }

    # Это похожа на ложно положительные срабатывания ClamAV
    my $exclude_codes = {
        "Heuristics.Broken.Executable" => 1,
    };

    if ($scan_result && $scan_result eq 'OK') {
        # все ок!
    } else {
        my $virus_name = $scan_result;
        $virus_name =~ s/\s+FOUND//;
        
        # Исключаем ложно положительные и сообщаем о вирусе
        unless ($exclude_codes->{ $virus_name } ) { 
            print_process_warning($pid, $status, "We found a virus: $scan_result");
        }
    }
}

# Проверим, чтобы все ПО запущенное на сервере было той же архитектуры, что и система на сервере
# Также проверяем на тип Elf файла и сообщаем о любом статически линкованном ПО
sub check_32bit_software_on_64_bit_server {
    my ($pid, $status) = @_;

    my $prefix = '';;

    if (defined($status->{envID}) && $status->{envID}) {
        $prefix = "/vz/root/$status->{envID}";
    }

    my $running_elf_file_architecture = '';

    # Мы делаем хак через pipe, чтобы file корректно работал с удаленными файлами и читал файл, а не симлинк
    my $elf_file_info = `cat /proc/$pid/exe| file -`;
    chomp $elf_file_info;

    # Если файл не существует или удален, то тупо скипаем эту проверку
    unless (-e "$prefix/$status->{fast_exe}") {
        return;
    }

    $running_elf_file_architecture = get_architecture_by_file_info_output($elf_file_info);

    my $running_elf_file_type = get_binary_file_type_by_file_info_output($elf_file_info);

    unless ($running_elf_file_type) {
        print_process_warning($pid, $status, "Can't get file type for: $pid raw output: $running_elf_file_type");
    }

    if ($running_elf_file_type && $running_elf_file_type eq 'static') {
        print_process_warning($pid, $status, "binary file for this process is $running_elf_file_type please CHECK this file because statically linked files is very often used by viruses");
    }

    unless ($status->{fast_container_architecture} eq $running_elf_file_architecture) {
        print_process_warning($pid, $status, "Programm is $running_elf_file_architecture on container with arch $status->{fast_container_architecture}  Probably it's an malware!");
    } 
 
}

# Проверяем, а не поменял ли процесс свое имя по тем или иным причинам, так часто любят делать malware
sub check_changed_proc_name {
    my ($pid, $status) = @_;

    my $prefix = '';

    if (defined($status->{envID}) && $status->{envID}) {
        $prefix = "/vz/root/$status->{envID}";
    }

    unless ($status->{fast_exe} && $status->{Name} ) {
        warn "Can't get process names\n";
        return;
    }

    # TODO:
    # bash на centos5 любит делать себе вот такое имя процеса: 
    # exe path: /bin/bash
    # cmdline: -bash 

    my $process_name_from_cmdline = '';
    
    # Если у нас есть пробелы, то мы можем извлечь имя команды, оно отделяется либо пробелами либо двоеточием
    if ($status->{fast_cmdline} =~ /[\s:]/) {
        $process_name_from_cmdline = (split /[\s:]/, $status->{fast_cmdline})[0];
    } else {

    }

    # в ps aux как раз отображается cmdline, поэтому его часто и подделывают, так что его и првоеряем :)

    # Системные (и не только) процессы любят делать вот так
    #exe path: /sbin/syslogd
    #cmdline: syslogd -m 0 

    my $programm_name_possible_faked = '';

    if ($status->{fast_cmdline} =~ m#^/#) {
        # Если в cmdline не красивое имя процесса, а путь до бинарика, то тут проверки очень простые

        # Тут хитрая сиутация возможна с симлинками, например:
        # exe path: /usr/lib/apache2/mpm-prefork/apache2
        # cmdline: /usr/sbin/apache2 -k start 
        # ls -al /usr/sbin/apache2
        # lrwxrwxrwx 1 root root 34 Sep 10  2013 /usr/sbin/apache2 -> ../lib/apache2/mpm-prefork/apache2

        # Но тут может быть засада, в имени в cmdline - имя симлинка, а вот в exe имя бинарика
        if (-l "$prefix/$process_name_from_cmdline") {
            my $real_progamm_path = readlink_deep("$prefix/$process_name_from_cmdline");

            # рекурсивный readlink нам выдает абсолютный путь на уровне ноды и его нужно подрезать
            $real_progamm_path =~ s#/vz/root/\d+/+#/#g;

            # Даже если после разрешения симлинков они не совпадают, то увы =(
            if ($real_progamm_path ne $status->{fast_exe}) {
                #warn "####Symlink check: $real_progamm_path $status->{fast_exe}\n";
                #$programm_name_possible_faked = 1;
                return print_process_warning($pid, $status, "process name from exe $status->{fast_exe} is not match to expanded from symlink: $real_progamm_path");
            }  
        } else {
            if ($process_name_from_cmdline ne $status->{fast_exe}) {
                $programm_name_possible_faked = 1;
            }
        }
    } else {
        # Если даже кусочка имени процесса нету в cmdline, то это зловред 
        unless ($status->{fast_exe} =~ m/$process_name_from_cmdline/) {
            $programm_name_possible_faked = 1;
        }
    }

    if ($programm_name_possible_faked) {
        print_process_warning($pid, $status, "process name from cmdline $process_name_from_cmdline is not equal to name from exe: $status->{fast_exe}");
    }
}

sub check_cwd {
    my $pid = shift;
    my $status = shift;
    
    my $process_name = $status->{Name};
    
    unless ( defined($good_cwd->{ $status->{fast_cwd} } ) ) {
        print "$pid $status->{fast_cwd} $status->{fast_exe} $process_name\n";
    }
}


# Построить хэш вида: inode-соединение для быстрого разрешения соединения по номеру inode
sub build_inode_to_socket_lookup_table {
    my $connections = shift;

    my $inode_to_socket = {};

    # В этом подходе есть еще большая проблема, дублирование inode внутри контейнеров нету, но
    # есть куча "потерянных" соединений, у которых владелец inode = 0, с ними нужно что-то делать
    for my $proto ('tcp', 'udp', 'unix') {
        for my $item (@{ $connections->{$proto} })  {
            if ($item->{inode} == 0) {
                # Да, такое бывает, для многих соединений inode == 0
                push @{ $inode_to_socket->{ 'orphan' } }, { type => $proto, connection => $item };
            } else {
                $inode_to_socket->{ $proto }->{ $item->{inode } } = $item;
            }
        }    
    }    

    return $inode_to_socket;
}

# Отображаем все "потерянные" соединения для определенного пространства имен
# Это нестандартный валидатор, он запускается отдельно от прочих
sub check_orphan_connections {
    my $container = shift;
    my $inode_to_socket = shift;

    my @normal_tcp_states_for_orphan_sockets = ('TCP_TIME_WAIT', 'TCP_FIN_WAIT2', 'TCP_SYN_RECV', 'TCP_LAST_ACK', 'TCP_FIN_WAIT1', 'TCP_CLOSE_WAIT', 'TCP_CLOSING');

    if ($inode_to_socket->{'orphan'} && ref $inode_to_socket->{'orphan'} eq 'ARRAY' && @{ $inode_to_socket->{'orphan'} } > 0 ) {
        SOCKETS_LOOP:
        for my $orphan_socket (@{ $inode_to_socket->{orphan} }) {
            # Skip unix sockets
            if ($orphan_socket->{type} eq 'unix') {
                next;
            }

            if ($orphan_socket->{type} eq 'tcp') {
                if (in_array($orphan_socket->{connection}->{state}, @normal_tcp_states_for_orphan_sockets)) {
                    next;
                } 

            }

            if ($orphan_socket->{type} eq 'tcp' or $orphan_socket->{type} eq 'udp') {
                if ($blacklist_listen_ports->{ $orphan_socket->{connection}->{rem_port} } or
                    $blacklist_listen_ports->{ $orphan_socket->{connection}->{local_port} }) {

                    if ($container) {
                        warn "Orphan socket TO/FROM DANGER port in: $container type $orphan_socket->{type}: " .
                            connection_pretty_print($orphan_socket->{connection}) . "\n";
                    } else {
                        warn "Orphan socket TO/FROM DANGER port type $orphan_socket->{type}: " .
                            connection_pretty_print($orphan_socket->{connection}) . "\n";
                    }    
                }
    
            }
            
        }    
    }    
}





1;
