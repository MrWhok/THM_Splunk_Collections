# THM_Splunk_Collections

## Table of Contents
1. [Splunk: Exploring SPL](#splunk-exploring-spl)


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
