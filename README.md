# THM_Splunk_Collections

## Table of Contents
1. [Splunk: Exploring SPL](#splunk-exploring-spl)
2. [Splunk 2](#splunk-2)
3. [Investigating with Splunk](#investigating-with-splunk)
4. [Incident Handling With Splunk](#incident-handling-with-splunk)
5. [Monitoring Active Directory](#monitoring-active-directory)
6. [Detecting AD Initial Access](#detecting-ad-initial-access)
7. [Detecting AD Lateral Movement](#detecting-ad-lateral-movement)
8. [Detecting AD Credential Attacks](#detecting-ad-credential-attacks)

## Splunk: Exploring SPL
### Search and Reporting
1. Submit your first query for All Time: index=windowslogs. How many total events do you see?

    The answer is `12256`.

2. After you submit your first query, look in the Fields sidebar. Which SourceIP has recorded the most amount of events?

    The answer is `172.90.12.11`.

3. How many events appear on 04/15/2022 from 08:05 AM to 08:06 AM?

    The answer is `134`.

### Search Operators
1. How many events in the windowslogs index have an EventID field value equal to 4624?

    We can use this filter:

    ```spl
    index=windowslogs EventID=4624
    ```
    The answer is `24`.

2. How many events are observed with the DestinationIp = 172.18.39.6 and DestinationPort = 135?

    We can use this filter:

    ```spl
    index=windowslogs DestinationIp=172.18.39.6 AND DestinationPort = 135
    ```
    The answer is `4`.

3. Use the query index=windowslogs Hostname=Salena.Adam DestinationIp=172.18.38.5. Which SourceIp returns the highest count?

    The answer is `172.90.12.11`.

4. How many events are returned when you search the term cyber*?

    We can use this filter:

    ```spl
    index=windowslogs cyber*
    ```
    The answer is `12256`.

5. Which operator is given the lowest priority in Splunk searches?

    The answer is `AND`.

### Filtering Results
1. Use the fields command to highlight Domain, SourceProcessId, and TargetProcessId. Which SourceProcessId has the highest value?

    We can use this filter:

    ```spl
    index=windowslogs | fields Domain SourceProcessId TargetProcessId
    ```
    The answer is `9496`.

2. Try out this query index=windowslogs | regex TargetObject="Manager$". Which TargetObject field value contains the highest number of results?


    We can use this filter:

    ```spl
    index=windowslogs | regex TargetObject="Manager$" | fields TargetObject
    ```
    The answer is `HKLM\SOFTWARE\Microsoft\SecurityManager`.

### Structuring Results
1. Build a table that highlights the EventID, AccountName, and AccountType fields. Which AccountName appears first in your results?

    We can use this filter:

    ```spl
    index=windowslogs | table EventID AccountName AccountType
    ```
    The answer is `SYSTEM`.

2. Append the above query to include the reverse command. Which EventID appears first?

    We can use this filter:

    ```spl
    index=windowslogs | table EventID AccountName AccountType | reverse
    ```
    The answer is `800`.

3. Use the query below to build a timeline of events. What password was given to the user A1berto?

    ```spl
    index=windowslogs EventID=1
    | table _time ParentProcessId ProcessId ParentCommandLine CommandLine
    | reverse
    ```
    We can find the password in the CommandLine field, which is `paw0rd1`.

### Transforming Commands
1. Use the top command to query the Image field. Which Image field value has the most occurrences?

    We can use this filter:

    ```spl
    index=windowslogs |  top Image
    ```
    The answer is `C:\windows\system32\svchost.exe`.

2. Try out the iplocation command with the SourceIp field. Which Region do the IP addresses in your events originate from?

    We can use this filter:

    ```spl
    index=windowslogs | iplocation SourceIp | stats count by Region
    ```
    The answer is `California`.

3. Try out this lookup query. Which Image field value has the highest RiskScore?

    ```spl
    index=windowslogs
    | lookup image_riskscore Image OUTPUT RiskScore
    | stats count by Image RiskScore
    | sort - RiskScore
    ```
    The answer is `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` with a RiskScore of `10`.

### Anomaly Detection
1. Run the first anomaly detection query (index=vpnlogs). Which other user is marked as an outlier?
    We can use this filter:

    ```spl
    index=vpnlogs
    | eventstats count as logins_by_user by user 
    | eventstats count as logins_by_user_country by user src_country 
    | eval country_freq=logins_by_user_country/logins_by_user
    | where country_freq < 0.1
    | table _time user src_ip src_country country_freq
    ```
    The answer is `jsmith`.

2. Which country is anomalous for the user from Q1? Answer Example: CN


    The answer is `JP`.

3. Run the second anomaly detection query (index=vpnlogs). Which user suspiciously logged in at 3 AM?

    We can use this filter:

    ```spl
    index=vpnlogs
    | eval hour=tonumber(strftime(_time, "%H")) + tonumber(strftime(_time, "%M"))/60
    | eventstats avg(hour) as typical_hour stdev(hour) as stdev_hour by user
    | eval zscore=abs(hour - typical_hour) / stdev_hour
    | where zscore > 3
    | eval hour=round(hour, 2), typical_hour=round(typical_hour, 2)
    | eval stdev_hour=round(stdev_hour, 2), zscore=round(zscore, 2)
    | table _time user src_ip src_country hour typical_hour stdev_hour zscore
    | sort - hour_zscore
    ```
    The answer is `njackson`.

## Splunk 2
### 100 Series Questions
1. Amber Turing was hoping for Frothly to be acquired by a potential competitor which fell through, but visited their website to find contact information for their executive team. What is the website domain that she visited?

    In here, we only have information the name is `Amber`. We need to know `Amber` ip, URL visited, or something else to find the answer. We can use the following query to find  `Amber` ip address:

    ```spl
    index="botsv2" amber sourcetype="pan:traffic" 
    |  dedup src_ip 
    | table src_ip
    ```
    The ip address is `10.0.2.101`. We can use this ip address to find the URL visited by `Amber`, the field name in here is not `URL`, but `site`:

    ```spl
    index="botsv2" 10.0.2.101 sourcetype="stream:HTTP" 
    | table site
    | dedup site
    ```
    The result still contains many rows. To reduce the number of rows, we can filter by using keyword the name of the same industry which is `beer`:

    ```spl
    index="botsv2" 10.0.2.101 sourcetype="stream:HTTP" *beer* | dedup site | table site
    ```
    It only returns one row, which is `www.berkbeer.com`. So the answer is `www.berkbeer.com`.

2. Amber found the executive contact information and sent him an email. What image file displayed the executive's contact information? Answer example: /path/image.ext

    We can use the following query to find the image file:

    ```spl
    index="botsv2" 10.0.2.101 sourcetype="stream:HTTP" www.berkbeer.com 
    ```
    We can check the `uri_path` field to find the image file, which is `/images/ceoberk.png`. So the answer is `/images/ceoberk.png`.

3. What is the CEO's name? Provide the first and last name.

    We need find the CEO's name from the email that amber sent to the CEO. So, we need to find amber email first. We can use the following query to find amber email:

    ```spl
    index="botsv2" amber sourcetype="stream:smtp"
    ```
    The amber email address is `aturing@froth.ly`. We can use this email address to find the CEO's name:

    ```spl
    index="botsv2"  aturing@froth.ly  sourcetype="stream:smtp" berkbeer
    ```

    ![alt text](<Assets/Splunk 2/1.png>)

    We can find the CEO's name in the email content, which is `Martin Berk`. So the answer is `Martin Berk`.

4. What is the CEO's email address?

    We can use the previous query to find the CEO's email address. The answer is `mberk@berkbeer.com`.

5. After the initial contact with the CEO, Amber contacted another employee at this competitor. What is that employee's email address?

    We can still use the question 3 query to find the email address of the other employee. The answer is `hbernhard@berkbeer.com`.

6. What is the name of the file attachment that Amber sent to a contact at the competitor?

    We can still use the question 3 query to find the file attachment. By checking the `attach_filename{}` field, we can find the file attachment name, which is `Saccharomyces_cerevisiae_patent.docx`. So the answer is `Saccharomyces_cerevisiae_patent.docx`.

7. What is Amber's personal email address?

    We can still use the question 3 query to find amber's personal email address. By checking the `content` field, we will find encoded content like this.

    ![alt text](<Assets/Splunk 2/2.png>)

    We can decode it by using cyberchef, and we will find the email address `ambersthebest@yeastiebeastie.com`.

### 200 Series Questions
1. What version of TOR Browser did Amber install to obfuscate her web browsing? Answer guidance: Numeric with one or more delimiter.

    We can use the following query to find the TOR Browser version:

    ```spl
    index="botsv2" amber tor *ver* |  reverse
    ```
    ![alt text](<Assets/Splunk 2/3.png>)

    We can see the TOR version is `7.0.4`.

2. What is the public IPv4 address of the server running www.brewertalk.com?

    We can use the following query to find the public IPv4 address of the server running www.brewertalk.com:

    ```spl
    index="botsv2" sourcetype="stream:HTTP" www.brewertalk.com 
    | reverse
    ```
    The answer is `52.42.208.228`.

3. Provide the IP address of the system used to run a web vulnerability scan against www.brewertalk.com.

    We can use the previous query and check the `http_user_agent` field. There is suspicious user agent `() { :;}; echo "shellshock: check"` which is a name of shell vulnerability. We can filter by using this user agent:

    ```spl
    index="botsv2" sourcetype="stream:HTTP" www.brewertalk.com  | reverse  | search http_user_agent="() { :;}; echo \"shellshock: check\""
    ```
    We can check the `src_ip` field to find the IP address. The answer is `45.77.65.211`.

4. The IP address from Q#2 is also being used by a likely different piece of software to attack a URI path. What is the URI path?Answer guidance: Include the leading forward slash in your answer. Do not include the query string or other parts of the URI. Answer example: /phpinfo.php

    We can use the following query to find the URI path:

    ```spl
    index="botsv2" src_ip="45.77.65.211" 
    | dedup uri_path 
    | table uri_path
    ```
    The answer is `/member.php`.

5. What SQL function is being abused on the URI path from the previous question?

    We can filter based on the URI path with SQL keyword and check the `form_data` field to find the SQL function. We can use the following query:

    ```spl
    index="botsv2" src_ip="45.77.65.211" 
    uri_path="/member.php" SQL
    | dedup form_data 
    | table form_data
    ```
    The answer is `updatexml`.

6. What was the value of the cookie that Kevin's browser transmitted to the malicious URL as part of an XSS attack? Answer guidance: All digits. Not the cookie name or symbols like an equal sign.

    There is common XSS tag like `<script>, <img>, <iframe>`, etc. We can filter by using these keywords:

    ```spl
    index="botsv2" kevin ("<script>" OR "<img>" OR "<iframe>")
    ```
    It only returns one row, and we can check the `cookie` field to find the cookie value, which is `1502408189`. So the answer is `1502408189`.

7. What brewertalk.com username was maliciously created by a spear phishing attack?

    We can check the `CSRF` token of `kevin` which is `1bc3eab741900ab25c98eee86bf20feb`. We can use this token to find the maliciously created username:

    ```spl
    index="botsv2" 1bc3eab741900ab25c98eee86bf20feb brewertalk.com 
    ```
    ![alt text](<Assets/Splunk 2/4.png>)

    The answer is `kIagerfield`.

### 300 Series Questions
1. Mallory's critical PowerPoint presentation on her MacBook gets encrypted by ransomware on August 18. What is the name of this file after it was encrypted?

    First, we need to find the host name of Mallory's MacBook. We can use the following query to find the host name:

    ```spl
    index="botsv2" mallory
    ```
    We will find the host name is `MACLORY-AIR13`. Then we can use this host name to find the name of the encrypted file:

    ```spl
    index="botsv2" host="MACLORY-AIR13" (*.ppt OR *.pptx)
    ```
    We can check the `TargetFilename` field to find the name of the encrypted file. The answer is `Frothly_marketing_campaign_Q317.pptx.crypt`.

2. There is a Games of Thrones movie file that was encrypted as well. What season and episode is it? 

    We can filter by adding the keyword `*.crypt` with common movies extensions type to find the the encrypted Games of Thrones movie file:

    ```spl
    index="botsv2" host="MACLORY-AIR13" *.crypt (*.mp4 OR *.mkv OR *.m4v OR *.mov)
    ```
    The answer is `S07E02`.

3. Kevin Lagerfield used a USB drive to move malware onto kutekitten, Mallory's personal MacBook. She ran the malware, which obfuscates itself during execution. Provide the vendor name of the USB drive Kevin likely used. Answer Guidance: Use time correlation to identify the USB drive.

    First, we can filter by using the keyword `usb` to find the possible USB driver used by Kevin:

    ```spl
    index="botsv2" kutekitten usb
    ```
    ![alt text](<Assets/Splunk 2/5.png>)

    We can see in the columns name field, there are 8 usb results. The story of the question state like this, `Hint: You know you have found the interesting file if the available field shows a count of 1.`. So we can start by checking `com.apple.driver.usb.cdc` and `com.apple.driver.ACPI_SMC_PlatformPlugin` which have a count of 1. The `com.apple.driver.ACPI_SMC_PlatformPlugin` return a result like this:

    ![alt text](<Assets/Splunk 2/6.png>)

    We can see the `Vendor`, `Model`, and `Serial` number of the USB drive. We can search in the google with this keyword `058f 6387 849083BA usb`. 

    ![alt text](<Assets/Splunk 2/7.png>)

    We can see the vendor name is `Alcor Micro Corp.`. So the answer is `Alcor Micro Corp.`.

4. What programming language is at least part of the malware from the question above written in?

    We can start by checking the user home directory of `kutekitten`. When we use the following query, we can find the user home directory is `/Users/mkraeusen`:

    ```spl
    index="botsv2" kutekitten
    ```
    We can add the user home directory to the previous query to narrow down the malware location:

    ```spl
    index="botsv2" kutekitten "\\/Users\\/mkraeusen" 
    ```
    If we check the `name` field, we will find interesting result `file_events`. We can add it to narrow down the result:

    ```spl
    index="botsv2" kutekitten "\\/Users\\/mkraeusen" name=file_events
    ```
    Then, we can check `columns.sha256` field to find the hash value of the file, which is `befa9bfe488244c64db096522b4fad73fc01ea8c4cd0323f1cbdee81ba008271`. 
    
    ![alt text](<Assets/Splunk 2/8.png>)

    We can search in the virus total to verify it.

    ![alt text](<Assets/Splunk 2/9.png>)

    Now it is confirmed that this hash is a malware file, and we can check the family label of this malware, which is `Perl`. So the answer is `Perl`.

5. When was this malware first seen in the wild? Answer Guidance: YYYY-MM-DD

    In the virus total, we can go to `details` -> `First Seen In The Wild`. The answer is `2017-01-17`.

6. The malware infecting kutekitten uses dynamic DNS destinations to communicate with two C&C servers shortly after installation. What is the fully-qualified domain name (FQDN) of the first (alphabetically) of these destinations?

    In the virus total, we can go to `Relations` -> `Contacted Domains` to find the C&C servers. The answer is `eidk.duckdns.org`.

7. From the question above, what is the fully-qualified domain name (FQDN) of the second (alphabetically) contacted C&C server?

    We can still find the second C&C server in the `Contacted Domains` section. The answer is `eidk.hopto.org`.

### 400 Series Questions
1. A Federal law enforcement agency reports that Taedonggang often spear phishes its victims with zip files that have to be opened with a password. What is the name of the attachment sent to Frothly by a malicious Taedonggang actor?

    We can use the following query to filter with `sourcetype="stream:smtp"` and `*.zip` keyword to find the suspicious email sent by Taedonggang:

    ```spl
    index="botsv2" sourcetype="stream:smtp" *.zip
    ```
    We can check `attach_filename{}` field to find the name of the attachment, which is `invoice.zip`. So the answer is `invoice.zip`.

2. What is the password to open the zip file?

    We can check the `content_body` field of the email to find the password. The answer is `912345678`.

3. The Taedonggang APT group encrypts most of their traffic with SSL. What is the "SSL Issuer" that they use for the majority of their traffic? Answer guidance: Copy the field exactly, including spaces.

    Since the story state like this:

    ```txt
    For this question, you will need the attacker's IP. Remember, there was an IP address scanning brewertalk.com. Use that IP address and search the TCP stream instead of the HTTP stream.
    ```
    We can use the IP address `45.77.65.211` and `sourcetype="stream:tcp"` to find the SSL traffic:

    ```spl
    index="botsv2" sourcetype="stream:tcp" 45.77.65.211
    ```
    We can check the `ssl_issuer` field to find the SSL Issuer, which is `C = US`. So the answer is `C = US`.

4. What is the first and last name of the poor innocent sap who was implicated in the metadata of the file that executed PowerShell Empire on the first victim's workstation? Answer example: John Smith

    The story already gives us link to find the answer.

    ![alt text](<Assets/Splunk 2/11.png>)

    The answer is `Ryan Kovar`.

5. Within the document, what kind of points is mentioned if you found the text?

    ![alt text](<Assets/Splunk 2/12.png>)


    The answer is `CyberEastEgg`.

6. To maintain persistence in the Frothly network, Taedonggang APT configured several Scheduled Tasks to beacon back to their C2 server. What single webpage is most contacted by these Scheduled Tasks? Answer example: index.php or images.html

    We can use the following query to find the creation of Scheduled Tasks:

    ```spl
    index="botsv2" schtasks.exe sourcetype=wineventlog 
    | table Process_Command_Line
    ```

    ![alt text](<Assets/Splunk 2/13.png>)

    We can see that there are several suspicious creation of scheduled task. We can filter by using `key_path` field with that registry path.

    ```spl
    index="botsv2" key_path="*\\Software\\Microsoft\\Network*"
    ```
    We can check `data` results which encrypted. We can decode it by using cyberchef. 

    ![alt text](<Assets/Splunk 2/14.png>)

    The answer is `process.php`.

## Investigating with Splunk
1. How many events were collected and Ingested in the index main?

    The answer is `12256`.

2. On one of the infected hosts, the adversary was successful in creating a backdoor user. What is the new username?

    We can filter by using EventID `4720` which is the event of creating a new user:

    ```spl
    index="main" EventID="4720"
    ```
    The answer is `A1berto`.

3. On the same host, a registry key was also updated regarding the new backdoor user. What is the full path of that registry key?

    The hostname of the infected host is `Micheal.Beaven`. We can filter by using this hostname and the keyword `A1berto`:

    ```spl
    index="main" Hostname="Micheal.Beaven" A1berto
    ```

    ![alt text](<Assets/Investigating with Splunk/1.png>)

    The answer is `HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto`.

4. Examine the logs and identify the user that the adversary was trying to impersonate.

    If we check all available users, we can find the user `Alberto` which is similar to the backdoor user `A1berto`. So the answer is `Alberto`.

5. What is the command used to add a backdoor user from a remote computer?

    We can filter by using the keyword `net user` which is a common command to add a user:

    ```spl
    index="main" A1berto "net user"
    ```
    ![alt text](<Assets/Investigating with Splunk/2.png>)

    The answer is `C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1`.

6. How many times was the login attempt from the backdoor user observed during the investigation?

    We can filter by using the EventID `4624` which is the event of successful login or EventID `4625` which is the event of failed login:

    ```spl
    index="main" (EventID="4624" OR EventID="4625") A1berto
    ```
    The answer is `0`.

7. What is the name of the infected host on which suspicious Powershell commands were executed?

    We can filter by using the keyword `powershell`:

    ```spl
    index="main" A1berto powershell
    ```
    Then, we can check the `Hostname` field to find the name of the infected host, which is `James.browne`. So the answer is `James.browne`.

8. PowerShell logging is enabled on this device. How many events were logged for the malicious PowerShell execution?

    We can filter by using the EventID `4103` which is the event of PowerShell Module Logging:

    ```spl
    index="main" EventID="4103"
    ```
    The answer is `79`.

9. An encoded Powershell script from the infected host initiated a web request. What is the full URL?

    We can extract the encoded PowerShell script and decode it by using cyberchef to find the URL. We can use the following query to extract the encoded PowerShell script:

    ```spl
    index="main" EventID="4103" Hostname="James.browne"
    | rex field=ContextInfo "Host Application\s*=\s*(?<Host_App>[^\r\n]+)"
    | stats values(Host_App) as "Extracted Host Applications"
    ```
    Once we extract the encoded PowerShell script, we can decode it by using cyberchef. We will find the URL is `hxxp[://]10[.]10[.]10[.]5/news[.]php`. We need to defang the URL to get the answer, which is `hxxp[://]10[.]10[.]10[.]5/news[.]php`.


## Incident Handling With Splunk
### Reconnaissance Phase
1. One suricata alert highlighted the CVE value associated with the attack attempt. What is the CVE value?

    In this case, we need to investigate reconnaissance of `imreallynotbatman.com` server. We already have suspicious ip address `40.80.148.42`. We can use the following query to narrow down the reconnaissance activity:

    ```spl
    index=botsv1 imreallynotbatman.com src=40.80.148.42 sourcetype=suricata
    ```
    We can check the `alert.signature` field to find the CVE value, which is `CVE-2014-6271`. So the answer is `CVE-2014-6271`.

2. What is the CMS our web server is using?

    We can use the following query to find the CMS of the web server by examining the `stream:http`:

    ```spl
    index=botsv1 imreallynotbatman.com sourcetype=stream:http
    ```
    ![alt text](<Assets/Incident Handling with Splunk/1.png>)

    We can see that `joomla` is mentioned in the `src_content` field. So the answer is `joomla`.

3. What is the web scanner, the attacker used to perform the scanning attempts?

    We can filter by using the suspicious ip address and check the `http_user_agent` field to find the web scanner:

    ```spl
    index=botsv1 imreallynotbatman.com sourcetype=stream:http src_ip=40.80.148.42 
    | dedup http_user_agent
    | table http_user_agent
    ```
    ![alt text](<Assets/Incident Handling with Splunk/2.png>)

    We can see that `acunetix` is mentioned in the `http_user_agent` field. So the answer is `acunetix`.

4. What is the IP address of the server imreallynotbatman.com?

    We can use the following query to find the IP address of the server and check the `dest_ip` field:

    ```spl
    index=botsv1 imreallynotbatman.com sourcetype=stream:http
    ```
    The answer is `192.168.250.70`.

### Exploitation Phase
1. What was the URI which got multiple brute force attempts?

    We can filter it by checking the `uri` field and counting the number of requests for each URI that has `http_method=POST` and destination ip address of the `iamreallynotbatman.com` server:

    ```spl
    index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST | stats count(uri) as Requests by uri | sort - Requests
    ```
    ![alt text](<Assets/Incident Handling with Splunk/3.png>)

    We can see that the most suspicious URI is `/joomla/administrator/index.php` since it is the admin panel of the joomla CMS and common target for brute force attack. We can make sure by checking it with this query:

    ```spl
    index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri="/joomla/administrator/index.php" | table _time uri src_ip dest_ip form_data
    ```
    ![alt text](<Assets/Incident Handling with Splunk/4.png>)

    We can see that there are many requests to this URI in the short period of time. So the answer is `/joomla/administrator/index.php`.

2. Against which username was the brute force attempt made?

    We can see the previous query already shows the `form_data` field which contains the username. The answer is `admin`.

3. What was the correct password for admin access to the content management system running imreallynotbatman.com?

    If we use this query below, we can extract the password from the `form_data` field by using `rex` command:

    ```spl
    index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST form_data=*username*passwd* | rex field=form_data "passwd=(?<creds>\w+)" |table _time src_ip uri http_user_agent creds
    ```
    ![alt text](<Assets/Incident Handling with Splunk/5.png>)

    There are only two `http_user_agent` values, `Python-urllib/2.7` and `Mozilla/5.0`. The mozilla user agent is more likely to be the successful login since it is a common user agent for web browser and it only has one request. The answer is `batman`.

4. How many unique passwords were attempted in the brute force attempt?

    The user agent `Python-urllib/2.7` is more likely to be the brute force attempt since it has many requests. It has ip address `23.22.63.114`. We can filter by using this user agent and ip address to find the unique passwords attempted in the brute force attempt:

    ```spl
    index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" src_ip="23.22.63.114" http_method=POST form_data=*username*passwd* | rex field=form_data "passwd=(?<creds>\w+)"  | dedup creds | table src_ip creds
    ```
    The answer is `412`.

5. What IP address is likely attempting a brute force password attack against imreallynotbatman.com?

    We already know the answer is `23.22.63.114` based on the previous analysis.

6. After finding the correct password, which IP did the attacker use to log in to the admin panel?

    We already know the answer is `40.80.148.42` based on question number 3.

### Installation Phase
1. Sysmon also collects the Hash value of the processes being created. What is the MD5 HASH of the program 3791.exe?

    By filtering with the attacker ip address that we have found in the previous question and filtering with the keyword `*.exe`, we can find the malicious `3791.exe` file. Then we can use the following query to extract the MD5 hash from the `Hash` field:

    ```spl
    index=botsv1 "3791.exe" sourcetype="XmlWinEventLog" EventCode=1
    ```
    The answer is `AAE3F5A29935E6ABCC2C2754D12A9AF0`.

2. Looking at the logs, which user executed the program 3791.exe on the server?

    We can check the `User` field to find the user that executed the program `3791.exe`.

    ```spl
    index=botsv1 "3791.exe" sourcetype="XmlWinEventLog" EventCode=1 AAE3F5A29935E6ABCC2C2754D12A9AF0
    ```
    The answer is `NT AUTHORITY\IUSR`.

3. Search hash on the virustotal. What other name is associated with this file 3791.exe?

    We can search the hash value `AAE3F5A29935E6ABCC2C2754D12A9AF0` in the virus total to find the other name associated with this file. The answer is `ab.exe`.

### Action on Objective
1. What is the name of the file that defaced the imreallynotbatman.com website ?

    The `iamreallynotbatman.com` server has ip address `192.168.250.70`. When we use it as a `src_ip` filter, we will find that this ip make connection to `23.22.63.114` which is the attacker ip address that we have found earlier. We can check the `uri` field to find the name of the file that defaced the website:

    ```spl
    index=botsv1 src=192.168.250.70 sourcetype=suricata dest_ip=23.22.63.114
    ```
    The answer is `poisonivy-is-coming-for-you-batman.jpeg`.

2. Fortigate Firewall 'fortigate_utm' detected SQL attempt from the attacker's IP 40.80.148.42. What is the name of the rule that was triggered during the SQL Injection attempt?

    We can filter by using the attacker ip address and `sourcetype=fortigate_utm` to find the rule that was triggered during the SQL Injection attempt:

    ```spl
    index=botsv1 src=40.80.148.42 sourcetype=fortigate_utm dest_ip=192.168.250.70 SQL
    ```
    We can check the `attack` field to find the name of the rule. The the answer is `HTTP.URI.SQL.Injection`.

### Command and Control Phase
1. This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?

    First we need to find out the malicious IP address used in this attack. We can check the `src_ip` and `dest_ip` field to find the malicious IP address that the installed binary is connecting to. We can use the following query to find the malicious IP address:

    ```spl
    index=botsv1 sourcetype=fortigate_utm"poisonivy-is-coming-for-you-batman.jpeg"
    ```
    We will get `dest_ip` which is `23.22.63.114` and `src_ip` which is `192.168.250.70`. We can use the following query to find the FQDN associated with this attack by using the malicious IP address:

    ```spl
    index=botsv1 sourcetype=stream:http dest_ip=23.22.63.114 src_ip=192.168.250.70
    ```
    We can check the `site` field to find the FQDN. The answer is `prankglassinebracket.jumpingcrab.com`.

### Weaponization Phase
1. What IP address has P01s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?

    `www.po1s0n1vy.com` is the domain that is returned when we search the attacke ip address`23.22.63.114` in the virusTotal database. So the answer is `23.22.63.114`.

2. Based on the data gathered from this attack and common open-source intelligence sources for domain names, what is the email address that is most likely associated with the P01s0n1vy APT group?

    We can use [alienvault](https://otx.alienvault.com/indicator/hostname/www.po1s0n1vy.com) to find the email address that is most likely associated with the P01s0n1vy APT group. The answer is `lillian.rose@po1s0n1vy.com`.

### Delivery Phase
1. What is the HASH of the Malware associated with the APT group?

    We can go to virustotal and check the attacker ip address that we have found so far, which is `23.22.63.114`.

    ![alt text](<Assets/Incident Handling with Splunk/6.png>)

    In the relations section, in the referring files, we can find the malware file with the name `	MirandaTateScreensaver.scr.exe`. We can check the hash value of this file, which is `c99131e0169171935c5ac32615ed6261`. The answer is `c99131e0169171935c5ac32615ed6261`.

2. What is the name of the Malware associated with the Poison Ivy Infrastructure?

    We have found it in the previous question, which is `MirandaTateScreensaver.scr.exe`. So the answer is `MirandaTateScreensaver.scr.exe`.

## Monitoring Active Directory
### Authentication Events
1. Which file stores domain user credentials on the domain controller?

    The answer is `NTDS.dit`.

2. A local user authenticates to a workstation. Will this generate any events on the Domain Controller? (Answer Format: Yea or Nay)

    The answer is `Nay`.

3. What Event ID is generated when a user requests a TGT?

    The answer is `4768`.

4. In win index in Splunk, how many unique accounts requested TGTs in the dataset across all time?

    We can use the following query to find the unique accounts that requested TGTs:

    ```spl
    index=* EventCode=4768
    | dedup Account_Name
    ```
    The answer is `14`.

### Accounts, Groups, and Resource Access Events
1. In Splunk, what field contains the group name?

    The answer is `Group_Name`.

2. In Splunk, what is the MOST common logon type in the dataset?

    We can use the following query to find the most common logon type in the dataset:

    ```spl
    index=* EventCode=4624
    | stats count by Logon_Type
    | sort -count
    ```
    The answer is `3`.

### Understanding Baseline Activity
1. What character suffix identifies computer accounts in AD?

    The answer is `$`.

2. Using Event ID 4769, what is the MOST frequently requested service?

    We can use the following query to find the most frequently requested service:

    ```spl
    index=* EventCode=4769 
    | stats count by Service_Name 
    | sort -count
    ```
    The answer is `THM-DC$`.

### Audit Policy Configuration
1. What command displays all current audit policy settings on a domain controller?

    The answer is `auditpol /get /category:*`.

### Scenario: New Employee Onboarding Audit
1. What is the name of the newly created account?

    We can filter by using the EventID `4720` which is the event of creating a new user:

    ```spl
    index=* EventCode=4720
    | table _time, SAM_Account_Name, Subject_Account_Name
    ```
    ![alt text](<Assets/Monitoring Active Directory/1.png>)

    The answer is `nathan.brooks`.

2.  Who created this account?

    We can see the `Subject_Account_Name` field in the previous query result. The answer is `adm-luke.sullivan`.

3. What group was this user added to?

    We can filter by using the EventID `4728`, `4732`, or `4756` which are the events of adding a user to a group:

    ```spl
    index=* (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
    | table _time, Member_Account_Name, Group_Name, Subject_Account_Name
    ```
    The answer is `Marketing`.

4. What was the source IP address of nathan.brooks's first TGT request?

    We can filter by using the EventID `4768` which is the event of requesting a TGT and the keyword `nathan`.

    ```spl
    index=* EventCode=4768 nathan
    ```

    Then we can check the `src_ip` field to find the source IP address of nathan.brooks's first TGT request, which is `10.5.50.12`.


## Detecting AD Initial Access
### Understanding IIS and its Logs
1. Where does IIS store access logs by default?

    The answer is `C:\inetpub\logs\LogFiles\W3SVC1`.

### Detecting Web Shell Deployment
1. What is the filename of the web shell the attacker used?

    First, we need to identify common attacker first step which is reconnaissance. We can use the following query to find the reconnaissance activity:

    ```spl
    index=iis sc_status=404
    | stats count by c_ip
    | sort - count
    ```
    We will find that there is one ip address `203.0.113.47`. Then we can use this ip address to find suspicious files by checking the `cs_uri_stem` field:

    ```spl
    index=iis c_ip=203.0.113.47 sc_status=200
    | stats count by cs_uri_stem
    | sort - count
    ```
    ![alt text](<Assets/Detecting AD Initial Access/1.png>)

    We can see that there is a suspicious file `shell.aspx` which is the web shell the attacker used. So the answer is `shell.aspx`.

2. What IP address was used to interact with the web shell?

    We have already found the ip address `203.0.113.47` in the previous question.

3. After accessing the web shell, what was the first reconnaissance command the attacker executed?

    We can use the following query to find the first reconnaissance command the attacker executed by checking the `cs_uri_stem` and `cs_uri_query`:

    ```spl
    index=iis c_ip=203.0.113.47 sc_status=200 cs_uri_stem="/aspnet_client/system_web/shell.aspx" 
    | table _time, c_ip, cs_uri_stem, cs_uri_query, sc_status
    | sort _time
    ```
    The answer is `whoami`.

### Exchange, OWA, and Credential Attacks
1. What virtual directory path provides access to the Exchange admin console? (Answer Format: /path)

    The answer is `/ecp`.

2. When investigating an OWA brute-force attack, IIS logs show the attacker's source IP but not the targeted username. Which Windows Event ID should you check to find the targeted account?

    We can check the EventID `4625` which is the event of failed login to find the targeted account.

### Detecting OWA Brute-Force Attacks
1. How many failed login attempts occurred during the OWA brute-force attack?

    We can examine the logs and filter by using the EventID `4625` which is the event of failed login:

    ```spl
    index=win EventCode=4625
    | stats count by user, Logon_Type
    | sort - count
    ```
    ![alt text](<Assets/Detecting AD Initial Access/2.png>)

    The answer is `15`.

2. What username was successfully compromised in this attack?

    In the previous question, we have found the highest targeted user is `sarah.kim`. We can check the EventID `4624` and `4625` to find the successful login attempt by this user:

    ```spl
    index=win EventCode IN (4624, 4625) user="sarah.kim" Logon_Type=8
    | table _time, EventCode, user, Process_Name, Logon_Type
    | sort _time
    ```
    ![alt text](<Assets/Detecting AD Initial Access/3.png>)

    We can see that there is a successful login attempt with EventID `4624`. So the answer is `sarah.kim`.

3. What source IP address conducted this brute-force attack?

    We can examine iis logs and filter by using the `cs_uri_stem` field with the value `/owa/auth.owa` and `cs_method=POST` to find the source IP address that conducted this brute-force attack:

    ```spl
    index=iis cs_uri_stem="/owa/auth.owa" cs_method=POST
    | bin _time span=5m
    | stats count by _time, c_ip
    | where count > 10
    | sort - count
    ```
    The answer is `203.0.113.47`.

4. After the successful login, what path did the attacker access to reach the Exchange admin console? (Answer Format: /path)

    We can use the following query to find the path that the attacker accessed to reach the Exchange admin console by filtering with the source IP address `203.0.113.47`:

    ```spl
    index=iis c_ip="203.0.113.47" 
    | table _time, cs_uri_stem
    | sort _time
    ```
    The answer is `/ecp`.

### VPN and Active Directory
1. What Windows Event ID indicates that NPS granted network access to a VPN user?

    The answer is `6272`.

2. In a typical enterprise VPN deployment, what protocol does the VPN gateway use to communicate authentication requests to NPS?

    The answer is `RADIUS`.

### Detecting VPN Credential Attacks
1. What username was successfully compromised via VPN after the credential attack?

    First, we need to find the targeted username by using brute-force attack. We can filter by using the EventID `6273` which is the event of failed login attempt:

    ```spl
    index=win EventCode=6273
    | stats count by User_Account_Name, Client_IP_Address
    | sort - count
    ```

    ![alt text](<Assets/Detecting AD Initial Access/4.png>)

    We can see that the most targeted user is `david.chen`. Then we can check the EventID `6272` and `6273` to find wether the user `david.chen` has a successful login attempt or not:

    ```spl
    index=win EventCode IN (6273,6272) User_Account_Name=david.chen
    | table _time, EventCode, User_Account_Name, Client_IP_Address
    ```
    ![alt text](<Assets/Detecting AD Initial Access/5.png>)

    We can see that there is a successful login attempt with EventID `6272`. So the answer is `david.chen`.

2. Based on the NPS access-accept event, at what time did the successful VPN authentication occur? (Answer Format: HH:MM:SS)

    We can check the `_time` field in the previous query to find the time of the successful VPN authentication, which is `10:47:06`.

### Investigating Challenge
1. What is the filename of the web shell the attacker deployed?

    First, we need to identify common attacker first step which is reconnaissance. We can use the following query to find the reconnaissance activity:

    ```spl
    index=iis sc_status=404
    | stats count by c_ip
    | sort - count
    ```
    We will find that there is one ip address `198.51.100.23`. Then we can use this ip address to find suspicious files by checking the `cs_uri_stem` field:

    ```spl
    index=iis c_ip=198.51.100.23 sc_status=200
    | stats count by cs_uri_stem
    | sort - count
    ```
    We will find a suspicious file `error.aspx` which is the web shell the attacker used. So the answer is `error.aspx`.

2. What was the first reconnaissance command the attacker executed through the web shell?

    We can use the following query to find the first reconnaissance command the attacker executed by checking the `cs_uri_stem` and `cs_uri_query`:

    ```spl
    index=iis c_ip=198.51.100.23 sc_status=200 cs_uri_stem="/aspnet_client/system_web/error.aspx" 
    | table _time, c_ip, cs_uri_stem, cs_uri_query, sc_status
    | sort _time
    ```
    The answer is `hostname`.

3. What URI path was used to upload the web shell to the server? (Answer Format: /path/file.ext)

    We can use the following query with the keyword `error.aspx` and `cs_method=POST` to find the URI path that was used to upload the web shell to the server:

    ```spl
    index=iis cs_method=POST cs_uri_query="*error.aspx*"
    | table _time, c_ip, cs_uri_stem, cs_uri_query, sc_status
    | sort _time
    ```
    ![alt text](<Assets/Detecting AD Initial Access/6.png>)

    We can check `cs_uri_stem` field The answer is `/internalapp/upload.aspx`.

4. At what time was the web shell file created on the server? (Answer Format: HH:MM:SS)

    We can check the `_time` field in the previous query to find the time when the web shell file was created on the server, which is `10:40:33`.


## Detecting AD Lateral Movement
### Discovery and Reconnaissance
1. What is the first discovery command the attacker executed?
 
    We can use the following query to find the common discovery command the attacker executed by checking the `CommandLine` field:

    ```spl
    index=win EventCode=1
    | search CommandLine IN ("*nltest*", "*net * user*", "*net * group*", "*net * view*", "*net * localgroup*")
    | table _time, host, User, Image, CommandLine, ParentImage
    ```
    The answer is `nltest  /domain_trusts`.

2. What is the full PowerShell command used to enumerate domain users?

    We can use the following query to find the PowerShell command used to enumerate domain users by filtering with the keyword `Get-ADUser`:

    ```spl
    index=win EventCode=4104
    | search Message IN ("*Get-ADUser*")
    | table _time, Message
    | sort _time
    ```
    The answer is `Import-Module ActiveDirectory; Get-ADUser -Filter * -Properties MemberOf | Select-Object Name, SamAccountName`.

### How Lateral Movement Works
1. What Logon Type in Event 4624 indicates a remote desktop session?

    The answer is `10`.

2. What Event ID, logged on the source system, records when a process uses alternate credentials to connect to a remote resource?

    The answer is `4648`.

### Detecting SMB Lateral Movement
1. What account was used to access the ADMIN$ shares?

    We can use the following query to find the account that was used to access the ADMIN$ shares by filtering with the keyword `ADMIN$`:

    ```spl
    index=win EventCode=5140 Share_Name IN ("*\\ADMIN$\*")
    | table _time, host, Source_Address, user, Share_Name
    | sort _time
    ```
    ![alt text](<Assets/Detecting AD Lateral Movement/1.png>)

    The answer is `luke.sullivan`.

2. Which user account was responsible for executing the lateral movement commands?

    In the previous, we have found the source address of the user that accessed the ADMIN$ shares is `10.5.50.12`. We can use it to find the machine hostname:

    ```spl
    index=win EventCode=4624 Source_Network_Address=10.5.50.12 user=*$
    | stats count by user, Source_Network_Address
    | sort -count
    ```
    ![alt text](<Assets/Detecting AD Lateral Movement/2.png>)

    We can see that the user account is `THM-MKT-WS$`. Then we can use this hostname to find the user account that was responsible for executing the lateral movement commands:

    ```spl
    index=win EventCode=1 host=THM-MKT-WS CommandLine="*ADMIN$*"
    | table _time, User, Image, CommandLine
    | sort _time
    ```
    ![alt text](<Assets/Detecting AD Lateral Movement/3.png>)

    The answer is `michelle.smith`.

### Detecting PsExec Lateral Movement
1. What was the destination host the attacker targeted via PsExec?

    We can use eventcode `7045` which is the event of service installation to find the destination host that the attacker targeted via PsExec:

    ```spl
    index=win EventCode=7045
    | table _time, host, Service_Name, Service_File_Name, Service_Type, Service_Start_Type, Service_Account
    | sort _time
    ```
    ![alt text](<Assets/Detecting AD Lateral Movement/4.png>)

    The answer is `THM-SQL-SRV`.

2. What is the first command that the attacker executed from the source machine using PsExec?

    First, we need to find the source machine that executed the PsExec command. We can use the following query to find the source machine by filtering with the destination host `THM-SQL-SRV` and eventcode `5145` which is the event of detailed file share access:

    ```spl
    index=win EventCode=5145 host=THM-SQL-SRV Relative_Target_Name="*PSEXE*"
    | table _time, user, Source_Address, Share_Name, Relative_Target_Name
    | sort _time
    ```

    ![alt text](<Assets/Detecting AD Lateral Movement/5.png>)

    We can see that the source address is `10.5.50.12`. We can use it to find the hostname of the source machine:

    ```spl
    index=win EventCode=4624 Source_Network_Address=10.5.50.12 user=*$
    | stats count by user, Source_Network_Address
    | sort -count
    ```
    The hostname output will be `THM-MKT-WS$`. Then we can use this hostname to find the first command that the attacker executed from the source machine using PsExec:

    ```spl
    index=win EventCode=1 host=THM-MKT-WS
    | search Image="*PsExec*"
    | table _time, host, User, Image, CommandLine
    | sort _time
    ```
    ![alt text](<Assets/Detecting AD Lateral Movement/6.png>)

    The answer is `C:\Tools\PsExec.exe  -accepteula \\THM-SQL-SRV cmd /c "hostname & whoami & ipconfig"`.

### Detecting RDP Lateral Movement
1. What is the source IP address of the RDP session that landed on the Domain Controller?

    In the THM it already stated that RDP session is investigated when something suspicious happened. So we dont investigate the RDP session by default. We can use the following query to find the suspicious command that the attacker executed by filtering with the EventCode `1` and the hostname of the domain controller `THM-DC`:

    ```spl
    index=win EventCode=1 host=THM-DC
    | search CommandLine IN ("*nltest*", "*net * user*", "*net * group*", "*net * view*")
    | table _time, host, User, Image, CommandLine, LogonId
    | sort _time
    ```
    ![alt text](<Assets/Detecting AD Lateral Movement/7.png>)

    We can see the `LogonId` field is `	0x508C55A`. We can use this logon id to identify how the attacker logged in to the domain controller. 

    ```spl
    index=win EventCode=4624 host=THM-DC Logon_ID=0x508C55A
    | table _time, user, Logon_Type, Source_Network_Address, Logon_ID
    ```
    The answer is `10.5.30.120`.

2. Tracing backward through the chain, what is the original source IP where the RDP chain began?

    We can use the following query to find the original source IP where the RDP chain began by filtering with the EventCode `4624` and the source ip address `10.5.30.120`:

    ```spl
    index=win EventCode=4624 Source_Network_Address=10.5.30.120 user=*$
    | stats count by user, Source_Network_Address
    | sort -count
    ```
    We will get the hotstname is `THM-SQL-SRV$`. Then we can use this hostname to find the LogonId of the RDP session:

    ```spl
    index=win EventCode=1 host=THM-SQL-SRV Image="*mstsc.exe*"
    | table _time, User, Image, CommandLine, LogonId
    | sort _time
    ```
    We will get the LogonId is `0x3C572BD`. We can use this logon id to find the source ip address of the RDP session:

    ```spl
    index=win EventCode=4624 host=THM-SQL-SRV Logon_ID=0x3C572BD
    | table _time, user, Logon_Type, Source_Network_Address, Logon_ID
    ```
    We will get the source ip address is `10.5.50.12`.

### Investigation Challenge
1. What is the full path of the service binary that was installed on the target?

    We can use the following query to find the full path of the service binary that was installed on the target by filtering with the EventCode `7045` which is the event of service installation:

    ```spl
    index=challenge svcupdate host="THM-SHR-SRV"  EventCode=7045 
    |  table Service_File_Name
    |  sort - Time  
    ```
    The answer is `%SystemRoot%\svcupdate.exe`.

2. What account was used to access the ADMIN$ share on the target server?

    We can use the following query to find the account that was used to access the ADMIN$ share on the target server by filtering with the EventCode `5140` which is the event of detailed file share access and the keyword `ADMIN$`:

    ```spl
    index=challenge EventCode=5140 Share_Name IN ("*\\ADMIN$\*")
    | table _time, host, Source_Address, user, Share_Name
    | sort _time
    ```

    ![alt text](<Assets/Detecting AD Lateral Movement/8.png>)

    The answer is `ryan.chen`.

3. What is the source IP address of the lateral movement to THM-SHR-SRV?

    We can found the answer in the previous query, which is `10.5.50.15`.

4. What is the first remote command the attacker executed on the target machine? (Answer Format: as shown in the CommandLine field)

    We can use the following query to find the first remote command the attacker executed on the target machine by filtering with the EventCode `1` and keyword `svcupdate` (the name of the service binary that was installed on the target):

    ```spl
    index=challenge EventCode=1 host=THM-SHR-SRV
    | search CommandLine IN ("*svcupdate*")
    | table _time, host, User, Image, CommandLine, LogonId
    | sort _time    
    ```

    ![alt text](<Assets/Detecting AD Lateral Movement/9.png>)

    The answer is `"cmd" /c "hostname & whoami & ipconfig"`.

5. What host did the attack originate from?

    In the previous query, we have found the `LogonId` field is `0x8C3EC`. We also get information the logon type is `3` which indicates an SMB or PsExec session. We can use this logon id to find the host that the attack originated from by filtering with the EventCode `4624`:

    ```spl
    index=challenge EventCode=4624 host=THM-SHR-SRV Logon_ID=0x8C3EC
    | table _time, user, Logon_Type, Source_Network_Address, Logon_ID
    ```
    We will get the source ip address is `10.5.50.15`. We can use this source ip address to find the hostname of the source machine:

    ```spl
    index=challenge EventCode=4624 Source_Network_Address=10.5.50.15 user=*$
    | stats count by user, Source_Network_Address
    | sort -count    
    ```
    The answer is `THM-HR-WS`.


## Detecting AD Credential Attacks
### Detecting Kerberoasting
1. How many service accounts were targeted by Kerberoasting?

    We can use the following query to find the unique service accounts that were targeted by Kerberoasting by filtering with the EventCode `4769` which is the event of requesting a service ticket and excluding the service accounts that have `$` in their name and `krbtgt` since they are not service accounts that in 5 minutes time span:

    ```spl
    index=task2 EventCode=4769 Service_Name!="*$" Service_Name!="krbtgt"
    | bin _time span=5m
    | stats dc(Service_Name) as unique_spns count by Account_Name, Client_Address, _time
    | where unique_spns > 5
    ```
    ![alt text](<Assets/Detecting AD Credential Attacks/1.png>)

    The answer is `9`.

2. What account requested the service tickets? (Answer Format: username only, without @domain)

    We can check the `Account_Name` field in the previous query to find the account that requested the service tickets, which is `emma.wilson`.

3. What source IP initiated the Kerberoasting?

    We can check the `Client_Address` field in the previous query to find the source IP that initiated the Kerberoasting, which is `10.5.90.1`.

### Detecting AS-REP Roasting
1. Which account had preauthentication disabled? (Answer Format: username)

    We can use the following query to find the account that had preauthentication disabled by filtering with the EventCode `4768` which is the event of requesting a TGT and checking the `Pre_Authentication_Type` field with value `0`:

    ```spl
    index=task3 EventCode=4768 Pre_Authentication_Type=0
    | table _time, Account_Name, Pre_Authentication_Type, Ticket_Encryption_Type, Client_Address
    ```
    The answer is `alex.reed`.

### Detecting LSASS Credential Dumping
1. What is the full path of the process that accessed lsass.exe?

    We can use the following query to find the full path of the process that accessed `lsass.exe` by filtering with the EventCode `10` which is the event of process access and checking the `TargetImage` field with value `*\\lsass.exe`:


    ```spl
    index=task4 EventCode=10 TargetImage="*\\lsass.exe"
    | stats count by SourceImage, GrantedAccess
    ```

    ![alt text](<Assets/Detecting AD Credential Attacks/2.png>)

    We can see the unusual process that accessed `lsass.exe` is `C:\Windows\Temp\procdump64.exe`. So the answer is `C:\Windows\Temp\procdump64.exe`.

2. What GrantedAccess value was used? (Answer Format: 0xNNNNNN)

    We can check the `GrantedAccess` field in the previous query to find the GrantedAccess value that was used, which is `0x1FFFFF`.

3. Which DLL in the CallTrace reveals the dump method?

    We can use the following query to find the DLL in the CallTrace that reveals the dump method by filtering with the EventCode `10` which is the event of process access and checking the `TargetImage` field with value `*\\lsass.exe` and `SourceImage` field with value `C:\Windows\Temp\procdump64.exe`:

    ```spl
    index=task4 EventCode=10 TargetImage="*\\lsass.exe" SourceImage=C:\\Windows\\Temp\\procdump64.exe
    | table _time, SourceImage, SourceUser, GrantedAccess, CallTrace
    ```
    The answer is `dbgcore.dll`.

### Detecting DCSync 
1. What account performed the DCSync?

    We can use the following query to find the account that performed the DCSync by filtering with the EventCode `4662` which is the event of object access and excluding the computer accounts that have `$` in their name:

    ```spl
    index=task5 EventCode=4662 "1131f6ad" user!="*$"
    | table _time, user, Access_Mask, Properties Logon_ID
    | sort _time
    ```

    ![alt text](<Assets/Detecting AD Credential Attacks/3.png>)

    The answer is `adm-luke.sullivan`.

2. What is the Logon_ID of the DCSync session? (Answer Format: 0xNNNNNNN)

    We can check the `Logon_ID` field in the previous query to find the Logon_ID of the DCSync session, which is `0x5A01668`.

3. What source IP initiated the DCSync?

    We can correlate the Logon_ID from the previous query with the EventCode `4624` which is the event of successful login to find the source IP that initiated the DCSync:

    ```spl
    index=task5 EventCode=4624 Logon_ID=0x5A01668
    | table _time, host, user, Source_Network_Address, Logon_Type
    ```
    The answer is `10.5.90.1`.

### Detecting NTDS.dit Extraction
1. What is the full command line used to extract NTDS.dit? (Answer Format: full command line as shown in Splunk)

    We can use the following query to find the full command line used to extract `NTDS.dit` by filtering with the EventCode `1` which is the event of process creation and checking the `Image` field with value `*\ntdsutil.exe`:

    ```spl
    index=task6 EventCode=1 Image="*\ntdsutil.exe"
    | table _time, host, User, ParentImage, Image, CommandLine
    ```
    The answer is `ntdsutil  "ac i ntds" "ifm" "create full C:\Perflogs\1" q q`.

2. What is the full shadow copy path the attacker copied ntds.dit from? (Answer Format: full path as shown in the CommandLine)

    We can use the following query to find the full shadow copy path the attacker copied `ntds.dit` from by filtering with the EventCode `1` which is the event of process creation and checking the `CommandLine` field with value `*HarddiskVolumeShadowCopy*` and `*ntds*` or `*SYSTEM*`:

    ```spl
    index=task6 EventCode=1 CommandLine="*HarddiskVolumeShadowCopy*" (CommandLine="*ntds*" OR CommandLine="*SYSTEM*")
    | table _time, host, User, ParentImage, Image, CommandLine
    ```
    ![alt text](<Assets/Detecting AD Credential Attacks/4.png>)

    The answer is `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy7\Windows\NTDS\ntds.dit`.

3. Where did the attacker stage the files copied from the shadow copy? (Answer Format: directory path)

    We can check the `CommandLine` field in the previous query to find where the attacker staged the files copied from the shadow copy, which is `C:\Windows\Temp`.

### Investigation Challenge
1. Which account was targeted by AS-REP Roasting?

    We can use the following query to find the account that was targeted by AS-REP Roasting by filtering with the EventCode `4768` which is the event of requesting a TGT and checking the `Pre_Authentication_Type` field with value `0`:

    ```spl
    index=task7 EventCode=4768 Pre_Authentication_Type=0
    | table _time, Account_Name, Pre_Authentication_Type, Ticket_Encryption_Type, Client_Address
    ```
    The answer is `mia.turner`.

2. What account performed the Kerberoasting? (Answer Format: username only, without @domain)

    We can use the following query to find the account that performed the Kerberoasting by filtering with the EventCode `4769` which is the event of requesting a service ticket and excluding the service accounts that have `$` in their name and `krbtgt` since they are produce large noise because they are Normal Kerberos traffic:

    ```spl
    index=task7 EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$" Service_Name!="krbtgt"
    | table _time, Account_Name, Service_Name, Ticket_Encryption_Type, Client_Address
    | sort _time
    ```

    ![alt text](<Assets/Detecting AD Credential Attacks/5.png>)

    The answer is `nathan.brooks`.

3. What process accessed LSASS on the workstation?

    We can use the following query to find the process that accessed `LSASS` on the workstation by filtering with the EventCode `10` which is the event of process access and checking the `TargetImage` field with value `*\\lsass.exe`:

    ```spl
    index=task7 EventCode=10 TargetImage="*\\lsass.exe"
    | stats count by SourceImage, GrantedAccess
    ```
    ![alt text](<Assets/Detecting AD Credential Attacks/6.png>)

    The answer is `rundll32.exe`.

4. What GrantedAccess value was used for the LSASS dump? (Answer Format: 0xNNNNNN)

    We can check the `GrantedAccess` field in the previous query to find the GrantedAccess value that was used for the LSASS dump, which is `0x1FFFFF`.

5. What account performed the DCSync attack?

    We can use the following query to find the account that performed the DCSync attack by filtering with the EventCode `4662` which is the event of object access and excluding the computer accounts that have `$` in their name:

    ```spl
    index=task7 EventCode=4662 "1131f6ad" user!="*$"
    | table _time, user, Access_Mask, Properties
    | sort _time
    ```

    ![alt text](<Assets/Detecting AD Credential Attacks/7.png>)

    The answer is `adm-luke.sullivan`.