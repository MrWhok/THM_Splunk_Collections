# THM_Splunk_Collections

## Table of Contents
1. [Splunk: Exploring SPL](#splunk-exploring-spl)
2. [Splunk 2](#splunk-2)


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