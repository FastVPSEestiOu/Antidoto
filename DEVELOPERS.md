Функции для решения тех или иных задач поиска зловредного ПО:

* parse_passwd_file: парсер /etc/passwd файлов
* get_server_processes: получение всех процессов, запущенных на VPS или сервере
* get_ips_for_container: получение всех IP для контейнера OpenVZ
* get_process_uid_or_gid: получение uid/gid процесса
* md5_file: получение ключевой суммы
* get_process_connections: получение всех соединений приложения (tcp, udp, unix)
* check_process_open_fd: получение всех открытых дескрипторов приложения
* get_url_last_part/get_url_basedir: вариации basedir
* get_proc_status: получение данных процесса из /proc/$pid/status в удобной форме хэша
* read_file_contents: считываем файл
* read_file_contents_to_list: считываем в массив
* list_all_in_dir: листинг файлов в папке
* get_running_containers_list: список запущенных на сервере OpenVZ контейнеров
* get_init_pid_for_container: получение pid init процесса контейнера 
* parse_udp_connections: парсер всех udp соединений сервера/контейнера
* parse_tcp_connections: парсер всех tcp соединений сервера/контейнера
# parse_unix_connections: парсер всех unix соединений сервера/контейнера
* readlink_deep: рекурсивный readlink()
* in_array: принадлежность элемента к массиву
