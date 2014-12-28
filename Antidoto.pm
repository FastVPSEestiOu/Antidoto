package Antidoto;

use strict;
use warnings;

use Digest::MD5 qw(md5_hex);

use Exporter qw(import);

our @EXPORT = qw(is_listen_connection is_loopback_address _hex2ip readlink_deep read_all_namespace_connections parse_tcp_connections
	parse_udp_connections parse_unix_connections get_init_pid_for_container get_running_containers_list list_all_in_dir list_files_in_dir  read_file_contents_to_list
    read_file_contents get_proc_status get_binary_file_type_by_file_info_output get_architecture_by_file_info_output get_url_last_part get_url_basedir get_process_connections
all_array_elements_is_equal get_process_uid_or_gid create_structure_hash parse_passwd_file get_server_processes get_ips_for_container md5_file get_file_size compare_two_hashes_by_list_of_fields
connection_pretty_print in_array build_inode_to_socket_lookup_table);

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


# Красивый "принтер" tcp/udp соединений
sub connection_pretty_print {
    my $connection = shift;

    my $print_string = '';
    my $state = '';

    # state у нас применим только к tcp, к udp он не применим
    if (defined($connection->{state})) {
        $state = "state: $connection->{state}";
    }
  
    if (is_listen_connection($connection)) {
        # Если это прослушка с хоста, то отобразим ее короче - remote IP тут совершенно не нужен
        $print_string = "type: $connection->{socket_type} listen on $connection->{local_address}:$connection->{local_port}";
    } else {
        $print_string = "type: $connection->{socket_type} local: $connection->{local_address}:$connection->{local_port} remote: $connection->{rem_address}:$connection->{rem_port} $state";
    }
 
    return $print_string;
}



# Проверка принадлежности элемента массиву
sub in_array {
    my ($elem, @array) = @_; 

    return scalar grep { $elem eq $_ } @array;  
}

# Получить размер файла
sub get_file_size {
    my $path = shift;

    my $size = (stat $path)[7];
    
    return $size;
}

# Сравниваем два хэша по заданному списку полей
sub compare_two_hashes_by_list_of_fields {
    my ($struct1, $struct2, @list_of_fields) = @_;

    for my $field (@list_of_fields) {
        if ($struct1->{$field} ne $struct2->{$field}) {
            return '';
        }    
    }    

    return 1;
}

sub md5_file {
    my $path = shift;

    unless ($path) {
        die "md5 failed";
    }   

    my $result = `md5sum $path`;
    chomp($result);

    my $md5 = (split /\s+/, $result)[0];

    return $md5;
}


# Получить все IP адреса, привязанные к конетейнеру
# Работает как со стороны ноды, так и изнутри OpenVZ котейнера
sub get_ips_for_container {
    my $ctid = shift;

    my $path = '/proc/vz/veinfo';

    my @veinfo = read_file_contents_to_list($path);
   
    #      39045     2    22              2a01:4f8:150:9222:0:0:0:13  178.63.152.133
    for my $line (@veinfo) {
        if ($line =~ m/^\s*$ctid/) {
            # Сотрем начальные пробелы
            $line =~ s/^\s+//g;
            my @data = split /\s+/, $line;

            # remove first 3 elements 
            for (1..3) {
                shift @data; 
            } 

            my @ips = @data;

            return @ips; 
        }
    }

    return ();
}
# Получить все процессы запущенные на сервере
sub get_server_processes {
    opendir my $proc_dir, "/proc" or die "Can't open /proc";

    my @processes_pids = ();

    PROCESSES_LOOP:
    while (my $pid = readdir($proc_dir)) {
        unless ($pid =~ m/^\d+$/) {
            next PROCESSES_LOOP;
        }

        # skip pseudo .. and .
        if ($pid =~ m/^\.+$/) {
            next PROCESSES_LOOP;
        }

        # Exclude this script
        if ($pid eq $$) {
            next PROCESSES_LOOP;
        }

        # Обязательно проверяем, чтобы псевдо-файл существовал
        # Если его нету, то это означает ни что иное, как остановку процесса 
        unless (-e "/proc/$pid") {
            next PROCESSES_LOOP;
        }

        push @processes_pids, $pid;
    }

    return @processes_pids;
}

# Хэшируем развесистую структуру, как в Java, но не особо красиво, конечно =)
sub create_structure_hash {
    my $structure = shift;

    # Магия! Но как сделать это красивее у меня мыслей особенно нет    
    return md5_hex(Dumper($structure));
}

# Парсим файл /etc/passwd
sub parse_passwd_file { 
    my $path = shift;

    my $users = {};
    my @lines = read_file_contents_to_list($path);

    PASSWD_READ_LOOP:
    for my $line (@lines) {
        my $user = {};

        # skip blank lines
        if (length ($line) == 0) {
            next;
        }

        # skip blank lines
        if ($line =~ m/^\s+$/) {
            next;
        }

        # ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
        # news:x:9:13:news:/etc/news: 
        @$user{'name', 'password', 'uid', 'gid', 'description', 'home', 'shell' } = split /:/, $line;
 
        unless (defined($user->{name}) && defined ($user->{uid}) && defined ($user->{gid})) {
            warn "Can't parse line: '$line' from passwd file: $path\n";
            next PASSWD_READ_LOOP;
        }
 
        # Дублирования происходить не должно ни при каком условии 
        if (defined($users->{ $user->{name } } ) ) {
            warn "Duplicate username $user->{name} in file $path\n";
        }
 
        $users->{ $user->{name} } = $user;
    }

    return $users;
}


sub get_architecture_by_file_info_output {
    my $elf_file_info = shift;

    my $running_elf_file_architecture = '';
    if ($elf_file_info =~ m/64-bit LSB/) {
        $running_elf_file_architecture = 'x86_64';
    } elsif ($elf_file_info =~ m/32-bit LSB/) {
        $running_elf_file_architecture = 'x86';
    } else {
        warn "We can't detect elf file architecture for $elf_file_info raw answer: $elf_file_info\n"; 
        $running_elf_file_architecture = 'unknown';
    }   

    return $running_elf_file_architecture;
}

sub get_process_uid_or_gid {
    my $requested_type = shift; # Uid / Gid
    my $status = shift;

    # Uid, Gid: Real, effective, saved set, and filesystem UIDs (GIDs).
    my @uids = split /\s+/, $status->{$requested_type};

    if (all_array_elements_is_equal(@uids)) {
        return $uids[0];
    } else {
        return -1;
    }
}

sub all_array_elements_is_equal {
    my @input = @_;

    if (scalar @input == 0) {
        1;
    }

    my $first_elem = $input[0];

    for my $elem (@input) {
        if ($elem ne $first_elem) {
            return '';
        }
    }

    return 1;
}

# Получить все сетевые соединения процесса
sub get_process_connections {
    my $pid = shift;
    my $inode_to_socket = shift;

    my $process_connections = [];

    opendir my $dir, "/proc/$pid/fd" or return;

    my @folders = grep { !/^\.\.?/ } readdir($dir);

    FILE_DESCRIPTORS_LOOP:
    for my $folder (@folders) {
        my $target = readlink "/proc/$pid/fd/$folder";

        unless (defined($target)) {
            next;
        }

        if ($target =~ m/^inotify$/) {
            next;
        }

        if ($target =~ m/^(pipe):\[\d+\]/) {
            next;
        }

        if ($target =~ m/^\[(?:eventpoll|inotify|timerfd|eventfd|signalfd)\]$/) {
            next;
        }

        if ($target =~ m/^anon_inode:\[?(?:eventpoll|inotify|timerfd|eventfd|signalfd)\]?/) {
            next;
        }

        if ($target =~ m/^(socket):\[(\d+)\]/) {
            my $inode = $2;

            my $found_socket = '';
            PROTO_LOOP:
            for my $proto ('udp', 'tcp', 'unix') {
                my $connection = $inode_to_socket->{$proto}->{ $inode };

                if ($connection) {
                    push @$process_connections, { type => $proto, connection => $connection };
                    $found_socket = 1;
                    last PROTO_LOOP;
                }

            }

            unless ($found_socket) {
                push @$process_connections, { type => 'unknown', raw_data => "$target" };
                next FILE_DESCRIPTORS_LOOP;
            }
        } else {
            # уберем префикс уровня ноды, чтобы получить данные внутри контейнера
            $target =~ s#/vz/root/\d+/?#/#g;
            push @$process_connections, { type => 'file', path => $target }
        }
    }

    # Отсортируем хэндлы по типу для красивой обработки далее
    @$process_connections = sort { $a->{type} cmp $b->{type} } @$process_connections;

    return $process_connections;
}
# Получить последнйи компонент URL
# /aaa/bbb/aaa/111/name
# и получаем: name
sub get_url_last_part {
    my $input_data = shift;
   
    my @data = split '/', $input_data;
    return $data[-1]; 
}

# Вернуть папку переданного пути
sub get_url_basedir {
    my $input_data = shift;

    my @data = split '/', $input_data;

    # Отбрасываем последний компонент
    pop @data;
    
    my $result_url = join '/', @data;

    return $result_url;
}

# Получить тип исполняемого файла - статически или динамически он линкован
sub get_binary_file_type_by_file_info_output {
    my $elf_file_info = shift;

    my $type = '';

    if ($elf_file_info =~ m/dynamically linked/) {
        return 'dynamic';
    } elsif ($elf_file_info =~ m/statically linked/) {
        return 'static';
    } else {
        return 'unknown';
    }
}  

#Aункция определяет, что за соединение ей передано - клиентское или прослушивающее
sub is_listen_connection {
    my $connection = shift;

    # С TCP все предельно просто - у него есть состояние соединения
    if ($connection->{socket_type} eq 'tcp' && $connection->{state} eq 'TCP_LISTEN') {
        return 1;
    }

    # А вот у UDP сэтим проблемы, нужно определять по внешним признакам
    if ($connection->{socket_type} eq 'udp') {
        if ( ($connection->{rem_address} eq '0.0.0.0' or $connection->{rem_address} eq '0:0:0:0:0:0:0:0' ) && $connection->{rem_port} eq '0') {
            return 1;
        } 
    }
    
    return '';
}

# Получить данные статуса процесса в виде хэша
sub get_proc_status {
    my $pid = shift;

    my @array = read_file_contents_to_list("/proc/$pid/status");
    my $status = {};

    unless  (scalar @array > 0) { 
        return '';
    }

    for my $line (@array) {
        my @data = split /:\s+/, $line, 2;
        $status->{$data[0]} = $data[1];
    }

    return $status;
}

# Считываем файл в переменную
sub read_file_contents {
    my $path = shift;

    my $res = open my $fl, "<", $path;

    unless ($res) {
        return '';
    }

    my $data;
    while (<$fl>) {
        chomp;
        $data .= $_;
    }

    if (defined $data) {
        chomp $data;
    }

    close $fl;

    return $data;
} 

# Считывем файл в массив
sub read_file_contents_to_list {
    my $path = shift;

    my $res = open my $fl, "<", $path;

    unless ($res) {
        return ();
    }

    my @data = <$fl>;
    chomp @data;
    close $fl;

    return @data;
}

# Лситинг файлов в папке
sub list_files_in_dir {
    my $path = shift;

    my $res = opendir(my $dir, $path);

    my @array = ();
    unless ($res) {
        return ();
    }
     
    while (my $element = readdir($dir)) {
        if ($element =~ /^\.+$/) {
            next;
        }

        unless (-f "$path/$element" ) {
            next;
        }

        push @array, $element;
    }

    closedir $dir;
    return @array;
}

# Лситинг всего в папке
sub list_all_in_dir {
    my $path = shift;

    my $res = opendir(my $dir, $path);

    my @array = (); 
    unless ($res) {
        return (); 
    }   
    
    while (my $element = readdir($dir)) {
        if ($element =~ /^\.+$/) {
            next;
        }   

        push @array, $element;
    }   

    closedir $dir;
    return @array;
}

# Получить список запущенных контейнеров
sub get_running_containers_list {
    my @list_raw = `/usr/sbin/vzlist -1`;
    my @list = (); 

    for my $ct (@list_raw) {
        $ct =~ s/^\s+//g;
        $ct =~ s/\s+$//g;

        push @list, $ct;
    }   

    return @list;
}

# Получить pid init процесса на ноде
sub get_init_pid_for_container {
    my $all_container_processes = shift;

    my $container_init_process_pid_on_node = ''; 

    # Более правильный путь перебрать все процессы и найти того, у которого vpid = 1 (это pid внутри контейнера)
    for my $pid_for_checking_init (@$all_container_processes) {
        my $status_info = get_proc_status($pid_for_checking_init);

        unless ($status_info) {
            next;
        }

        if ($status_info->{VPid} eq 1) {
            #print "We found init for $container: $pid_for_checking_init!\n";
            $container_init_process_pid_on_node = $pid_for_checking_init;
            last;
        }   
    }   

    return $container_init_process_pid_on_node;
}

# Парсим файлы из /proc с целью извлечь всю информацию о соединениях
sub parse_udp_connections {
    my $pid = shift;

    my @files_for_reading = ();

    if (defined($pid) && $pid) {
        @files_for_reading = ("/proc/$pid/net/udp", "/proc/$pid/net/udp6"); 
    } else {
        @files_for_reading = ("/proc/net/udp", "/proc/net/udp6");
    }

    my $udp_connections = [];
    
    for my $udp_file_stat_name (@files_for_reading) {
        my $res = open my $fl, "<", $udp_file_stat_name;

        unless ($res) {
            return $udp_connections; 
        }

        for my $line (<$fl>) {
            my $udp_connection = {};

            chomp $line;
            #  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops             
            #    1: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 3941318127 2 ffff880284682bc0 0     
    
            # Skip header 
            if ($line =~ /^\s+sl\s+local_address/) {
                next;
            }

            my @matches = $line =~ m/
                ^\s*(\d+):\s+                   # number of record
                ([\dA-F]{8,32}):([\dA-F]{4})\s+ # local_address  8 - ipv4, 32 - ipv6
                ([\dA-F]{8,32}):([\dA-F]{4})\s+ # remote_address 8 - ipv4, 32 - ipv6
                ([\dA-F]{2})\s+                 # st
                ([\dA-F]{8}):([\dA-F]{8})\s+    # tx_queue, rx_queue
                (\d+):([\dA-F]{8})\s+           # tr and tm->when
                ([\dA-F]{8})\s+                 # retransmit
                (\d+)\s+                        # uid
                (\d+)\s+                        # timeout
                (\d+)\s+                        # inode
                (\d+)\s+                        # ref
                ([\dA-F]+)\s+                   # pointer
                (\d+)                           # drops
            /xi;

            if (scalar @matches == 0) {
                warn "Can't parse udp connection line: $line\n";
                next;
            }

            @$udp_connection{ 'sl', 'local_address', 'local_port', 'rem_address', 'rem_port', 'st', 'tx_queue', 'rx_queue', 'tr', 'tm_when', 'retrnsmt', 'uid', 'timeout', 'inode', 'ref', 'pointer', 'drops' } = @matches; 

            # Конвертируем удаленный/локальный адреса в нормальный форамат
            for my $address_type ('local_address', 'rem_address') {
                $udp_connection->{$address_type} = _hex2ip($udp_connection->{$address_type });
            }

            # Тут все закодировано чуточку проще
            for my $port_type ('local_port', 'rem_port') {
                $udp_connection->{$port_type} = hex $udp_connection->{$port_type};
            }

            # Псевдопеременная, для упрощения обработки впредь
            $udp_connection->{socket_type} = 'udp';

            push @$udp_connections, $udp_connection;
        }

        close $fl;
    }

    #print Dumper($udp_connections);
    return $udp_connections;
}

sub parse_unix_connections {
    my $pid = shift;

    my $path = '';
    if (defined($pid) && $pid) {
        $path = "/proc/$pid/net/unix";
    } else {
        $path = '/proc/net/unix';
    }

    my $unix_connections = [];

    my $res = open my $fl, "<", $path;
    unless ($res) {
        return $unix_connections;
    }

    for my $line (<$fl>) {
        chomp $line;

        if ($line =~ m/^\s*Num\s+RefCount\s+Protocol/) {
            next;
        }

        my $unix_connection = {};

        # Num       RefCount Protocol Flags    Type St Inode Path
        # ffff880184824100: 00000002 00000000 00000000 0002 01 3492802135 @/org/kernel/udev/udevd
        # ffff8807afa05600: 00000002 00000000 00000000 0002 01 3937453950
        # ffff880c35b6cbc0: 0000000C 00000000 00000000 0002 01 10609 /dev/log
        my @matches = $line =~ m/
            ^\s*
            ([\dA-F]{8,16}):\s+    # Num
            ([\dA-F]{8})\s+      # RefCount
            (\d{8})\s+           # Protocol
            (\d{8})\s+           # Flags
            (\d{4})\s+           # Type
            (\d{2})\s+           # St
            (\d+)\s*             # Inode
            (.*?)$               # Path
        /xi;

        if (scalar @matches == 0) {
            warn "Can't parse unix connection line: $line\n";
            next;
        }

        @$unix_connection{ 'num', 'refcount', 'protocol', 'flags', 'type', 'st', 'inode', 'path' } = @matches;
        # Псевдопеременная, для упрощения обработки впредь
        $unix_connection->{socket_type} = 'unix';

        push @$unix_connections, $unix_connection;;
    }

    close $fl;

    return $unix_connections;
}

sub parse_tcp_connections {
    my $pid = shift;
    
    my @files_for_reading = ();

    if (defined($pid) && $pid) {
        @files_for_reading = ("/proc/$pid/net/tcp", "/proc/$pid/net/tcp6");
    } else {
        @files_for_reading = ("/proc/net/tcp", "/proc/net/tcp6");
    }

    # Спец массив для отображения человеко-понятных статусов
    # http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/include/net/tcp_states.h?id=HEAD
    my @tcp_status_names = (
        undef,
        'TCP_ESTABLISHED',
        'TCP_SYN_SENT',
        'TCP_SYN_RECV',
        'TCP_FIN_WAIT1',
        'TCP_FIN_WAIT2',
        'TCP_TIME_WAIT',
        'TCP_CLOSE',
        'TCP_CLOSE_WAIT',
        'TCP_LAST_ACK',
        'TCP_LISTEN',
        'TCP_CLOSING',
    );

    my $tcp_connections = [];
   
    for my $tcp_file_stat_name (@files_for_reading) {
        my $res = open my $fl, "<", $tcp_file_stat_name;

        unless ($res) {
            return $tcp_connections; 
        }

        for my $line (<$fl>) {
            my $tcp_connection = {};

            chomp $line;
  
            #   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
            # 0: 00000000:7275 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 32793258 1 ffff8854feba98c0 99 0 0 10 -1         
 
            # Skip header 
            if ($line =~ /^\s+sl\s+local_address/) {
                next;
            }
    
            # 5977: 33DD242E:0050 859E2459:CF01 01 00000000:00000000 00:1AD7F29ABCA 00000000    33        0 3912372353 1 ffff882be39ec400 179 3 9 10 -
            #   445:  00000000:1622 00000000:0000 0A 00000000:00000000 00:00000000 00000000    -1        0 23890959 1 ffff880a5d74c100 99 0 0 10 -1                  
            my @matches = $line =~ m/
                ^\s*(\d+):\s+                # number of record
                ([\dA-F]{8,32}):([\dA-F]{4})\s+ # local_address  8 - ipv4, 32 - ipv6
                ([\dA-F]{8,32}):([\dA-F]{4})\s+ # remote_address 8 - ipv4, 32 - ipv6
                ([\dA-F]{2})\s+              # st
                ([\dA-F]{8}):([\dA-F]{8})\s+ # tx_queue, rx_queue
                (\d+):([\dA-F]{8,11})\s+     # tr and tm->when
                ([\dA-F]{8})\s+              # retransmit
                (\-?\d+)\s+                  # uid, да, тут может быть отрицальное число
                (\d+)\s+                     # timeout
                (\d+)\s+                     # inode
                (.*?)\s*$                    # other stuff
                /xi;

            if (scalar @matches == 0) {
                warn "Can't parse tcp connection line: $line\n";
                next;
            }

            @$tcp_connection{ 'sl', 'local_address', 'local_port', 'rem_address', 'rem_port', 'st', 'tx_queue', 'rx_queue', 'tr', 'tm_when', 'retrnsmt', 'uid', 'timeout', 'inode', 'other' } = @matches; 

            # Конвертируем удаленный/локальный адреса в нормальный форамат
            for my $address_type ('local_address', 'rem_address') {
                $tcp_connection->{$address_type} = _hex2ip($tcp_connection->{$address_type });
            }

            # Тут все закодировано чуточку проще
            for my $port_type ('local_port', 'rem_port') {
                $tcp_connection->{$port_type} = hex $tcp_connection->{$port_type};
            }

            # Преобразуем в понятное значение
            $tcp_connection->{state} = $tcp_status_names[ hex $tcp_connection->{st} ];

            #print "$tcp_connection->{st} => $tcp_connection->{state}\n"; 

            unless ($tcp_connection->{state}) {
                warn "Can't get correct connection status for: $tcp_connection->{st}\n";
            }

            # print Dumper($tcp_connection);
            # Псевдопеременная, для упрощения обработки впредь
            $tcp_connection->{socket_type} = 'tcp';
    
            push @$tcp_connections, $tcp_connection;
        }

        close $fl;
    }

    return $tcp_connections;
}



# Получаем все типы соединений для данного неймспейса (в случае указания pid) или всего сервера
sub read_all_namespace_connections {
    my $pid = shift;

    my $connections = {};

    $connections->{tcp}  = parse_tcp_connections($pid);
    $connections->{udp}  = parse_udp_connections($pid);
    $connections->{unix} = parse_unix_connections($pid);

    return $connections;    
}

# Улучшенная версия рекурсивного readlink, которая обходит пути до упора, пока не найдем искомый файл
sub readlink_deep {
    my $path = shift;

    # Если это не симлинк, то вернем сам путь и наша задача решена
    unless (-l $path) {
        return $path;
    }    

    my $target = readlink($path);

    # Рекурсия здесь для таких случаев:
    # /usr/bin/java -> /etc/alternatives/java
    # /etc/alternatives/java -> /usr/lib/jvm/jre-1.7.0-openjdk/bin/java

    if ($target) {
        # Получим базовое имя "все до последнего компонента пути"
        my $path_basename = get_url_basedir($path);

        # /usr/sbin/apache2 -> ../lib/apache2/mpm-prefork/apache2
        if ($target =~ m/^\.{2}/) {
            my $get_up_folder = get_url_basedir($path_basename);

            # заменяем две точки на папку уровнем выше 
            $target =~ s/^\.{2}/$get_up_folder/;

            return readlink_deep($target);
        }    
 
        #  /usr/bin/python -> python2.6
        unless ($target =~ m#^/#) {
            return readlink_deep("$path_basename/$target"); 
        }    

        return readlink_deep($target);
    } else {
        # Если не смогли перейти по ссылке, то возвращаемся к исходному файлу
        return $path;
    }    
}

# Проверка адреса на принадлежность loopback интерфейсу
sub is_loopback_address {
    my $address = shift;

    if ($address && ( $address eq '127.0.0.1' or $address eq '::1' or $address eq '0:0:0:0:0:0:0:1')) {
        return 1;
    }

    return '';
}

# Copy & paste from: http://cpansearch.perl.org/src/SALVA/Linux-Proc-Net-TCP-0.05/lib/Linux/Proc/Net/TCP.pm
sub _hex2ip {
    my $bin = pack "C*" => map hex, $_[0] =~ /../g;
    my @l = unpack "L*", $bin;
    if (@l == 4) {
        return join ':', map { sprintf "%x:%x", $_ >> 16, $_ & 0xffff } @l;
    }
    elsif (@l == 1) {
        return join '.', map { $_ >> 24, ($_ >> 16 ) & 0xff, ($_ >> 8) & 0xff, $_ & 0xff } @l;
    }
    else { die "internal error: bad hexadecimal encoded IP address '$_[0]'" }
}

1;