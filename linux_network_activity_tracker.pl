#!/usr/bin/perl

use strict;
use warnings;

use Antidoto;

my $blacklist_listen_ports = {
    #1080  => 'socks proxy',
    #3128  => 'http proxy',
    6666  => 'irc',
    6667  => 'irc alternative',
    9050  => 'tor',
    # botnet melinda & bill gates https://github.com/ValdikSS/billgates-botnet-tracker/blob/master/gates/gates.py
    36008 => 'botnet melinda & bill gates',
    4443 => '/tmp/.estbuild/lib/ld-linux.so.2 rooted',
};

my @running_containers = get_running_containers_list();

CONTAINERS_LOOP:
for my $container (@running_containers) {
    if ($container eq '1' or $container eq '50') {
        # Skip PCS special containers
        next;
    }

    my @ct_processes_pids = read_file_contents_to_list("/proc/vz/fairsched/$container/tasks");
    my $container_init_process_pid_on_node = get_init_pid_for_container(\@ct_processes_pids);
    my $container_connections = read_all_namespace_connections($container_init_process_pid_on_node);

    my $inode_to_socket = build_inode_to_socket_lookup_table($container_connections);

    for my $pid (@ct_processes_pids) {
    	# Получаем удобный для обработки список дескрипторов (файлов+сокетов) пороцесса
    	my $process_connections = get_process_connections($pid, $inode_to_socket);

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
                	#if (is_loopback_address($connection->{local_address})) {
                    # 	next CONNECTIONS_LOOP;
                	#}    

                	if (my $port_description = $blacklist_listen_ports->{ $connection->{local_port} }) {
                		print "Container's $container process $pid listens DANGER $connection->{socket_type} port $connection->{local_port}\n";
                	}
            	} else {
                	# Это может быть внутренее соединение, которое не интересно нам при анализе
                	#if (is_loopback_address($connection->{rem_address})) {
                    #	next CONNECTIONS_LOOP;
                	#}

                	# client socket
                	if (my $port_description = $blacklist_listen_ports->{ $connection->{rem_port} }) {
                		print "Container's $container process $pid connected to the DANGER $connection->{socket_type} port $connection->{rem_port} to the server $connection->{rem_address}\n";
                	}
            	}
        	}
        }
	}	
}
