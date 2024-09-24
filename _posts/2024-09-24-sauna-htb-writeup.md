---
layout: post
title: HTB Sauna writeup
lang: en
categories: [Offensive, HTB]
tags: [windows, active-directory, preauth ,kerberoasting, kerberos, DCSync, lsass]
permalink: /posts/2024-09-24-sauna-htb-writeup
---


## Intro
Hello hackers! In this HTB easy machine, we are going to be exploiting kerberos 'No preauth' users, enumerating with winPEAS and dumping LSASS with mimikatz. This was a pretty strait forward box, but is a good intro for people newer to Active Directory penetration testing.

## Enumeration 

### Nmap
![5262bc92c9b2ea4caec50d3b36259a2a.png]({{ site.baseurl }}/images/5262bc92c9b2ea4caec50d3b36259a2a.png)

We have several ports open, there is a website, which is basically a langing page and contains nothing, the forms don't work and no directory or vhost bruteforcing helps with that. So I'm not gonna add screenshots. (to save you time)

### Kerberos *(port 88)*

We see that the kerberos port is open, which is normal for an active directory, DC server. Let's enumerate users with kerbrute.

*This works because kerberos returns different responses if a password is wrong or if a user does not exist, which allows us to determine existing users.*

![35140c9f877992cdcc91ea4c8e80a38e.png]({{ site.baseurl }}/images/35140c9f877992cdcc91ea4c8e80a38e.png)

We have found several users, now let's run them through impacket's `GetNPUsers` script, it will show us if there are any users from our list that do not require kerberos pre authentication. If one of the users has that, it will allow us to obtain a hash for that user, which we can crack.

![15cff336b8d06043d7e39dbce3c77cee.png]({{ site.baseurl }}/images/15cff336b8d06043d7e39dbce3c77cee.png)

As you can see we are lucky and the user `fsmith` has *DONT_REQUIRE_PREAUTH* set, which allows us to get his hash and crack it with hashcat.

```bash
hashcat -m 18200 -a 0  loot/fsmith.krb5 /usr/share/wordlists/rockyou.txt -o loot/fsmith.recovered
```

![9fbdc04c02a76e987f8f124cef130803.png]({{ site.baseurl }}/images/9fbdc04c02a76e987f8f124cef130803.png)

![10948e3334043a73684c624ec48e626e.png]({{ site.baseurl }}/images/10948e3334043a73684c624ec48e626e.png)

We obtain credentials for a user: `fsmith:Thestrokes23`

We check them against SMB, which shows us a few shares, only the RICOH one is non standad, but we have no access to it, so lets keep going.
![8b3af34906fb47b49b23050fd629cc9d.png]({{ site.baseurl }}/images/8b3af34906fb47b49b23050fd629cc9d.png)

We check for winrm, and it seems to work,  so lets remote into the machine.
![d8a1e9b0b461c9d4e8403f47d6a66081.png]({{ site.baseurl }}/images/d8a1e9b0b461c9d4e8403f47d6a66081.png)
![e9599cd11a7911c7e75f890b91a4e8a7.png]({{ site.baseurl }}/images/e9599cd11a7911c7e75f890b91a4e8a7.png)
User flag captured.

When we run winPEAS, it alerts us to the fact that autologon credentials are saved in the registry. The username `svc_loanmanager` is very similar to an account that we've seen, `svc_loanmgr`
![c40f364175a439b7ea837274d15fa2a3.png]({{ site.baseurl }}/images/c40f364175a439b7ea837274d15fa2a3.png)

`svc_loanmgr:Moneymakestheworldgoround!`

Lets run bloodhound and have a look at some privesc vectors that we may have from this account.

![c32c7e69890122fd641588d00ffa2968.png]({{ site.baseurl }}/images/c32c7e69890122fd641588d00ffa2968.png)
We can see that the account we captured has DCSync rights over the domain, which is basically a function that allows domain controllers to sync with each other. We can exploit this right with mimikatz by dumping LSASS to get credentials.

![9e1f4cb1833e9aafc65af9aba8dab523.png]({{ site.baseurl }}/images/9e1f4cb1833e9aafc65af9aba8dab523.png)
As you can see, the user svc_loanmgr has remoting enabled, so let's start a beacon as this user and dump lsass.

![01c04d24d98b90b49bcaa2e43719b756.png]({{ site.baseurl }}/images/01c04d24d98b90b49bcaa2e43719b756.png)
As you can see we have obtained some hashes but no password. We don't need to crack this hash in order to get a shell as the Administrator. We can just pass the hash, in this case using evil-winrm

![5ce409c4f591accc96667915ba14e868.png]({{ site.baseurl }}/images/5ce409c4f591accc96667915ba14e868.png)
And we get a shell as Administrator!
Pwned.

***
## Bonus

#### Kerberoasting
For some reason, hsmith is a service account, and we are able to kerberoast him using FSmith's credentials, however this proves useless.

![e6c3750df687be360f4b4f9414fe3aaa.png]({{ site.baseurl }}/images/e6c3750df687be360f4b4f9414fe3aaa.png)

```bash
hashcat -m 13100 --force -a 0 hashes.kerberoast /usr/share/wordlists/rockyou.txt

```

![23c64eaf25e268af9b6901f3e7b91eca.png]({{ site.baseurl }}/images/23c64eaf25e268af9b6901f3e7b91eca.png)
*Same password? WTF XD*

#### Shell as SYSTEM
We could also get a shell as *NT AUTHORITY\SYSTEM* with PSexec in the last step, it also allows to pass the hash.
