<p align='left'>
  <img src='./Images/Pasted%20image%2020260503004701.png'>
</p>


# Scenario:
 *Welcome to this hands-on Splunk challenge room. In this scenario, you've just completed your third screening interview for a SOC Level 2 role at MSSP Cybertees Ltd, and you're now faced with the final assessment to test your knowledge. You'll be given access to a Splunk instance receiving network logs from an unknown source. The data isn't arriving in a usable state, so before you can analyze what's happening on the network, you must Fixit!* (🫡 Okay)

Room: https://tryhackme.com/room/fixit
## *Objectives*

*This challenge is divided into three phases*

1. ***Fix event boundaries** for the incoming logs* (a little confusing at first)
2. ***Extract custom fields** from the available events* (😲 the Hard part)
3. ***Analyze event data** to uncover network activity* (the usual easy SOC stuff)

## Phase 1: Fixing Event Boundaries

*The first phase of your challenge is to fix the event boundaries for the incoming logs. As seen in the screenshot below and in your Splunk instance, the raw data is being ingested and Splunk cannot determine where one event ends and the next begins, making the data impossible to analyze. Go ahead and jump into the Fixit app's configuration files to get started!*

After running the network-logs binary we get the output:

```
[Network-log]: User named Emily Clark from Finance department accessed the resource Cybertees.THM/contact.html from the source IP 192.168.1.4 and country 
Japan at: Mon Dec  1 10:13:38 2025
```

We also see that in Splunk **Search and Reporting** section shows the event entries in two consistent parts, 1st event line `[Network-log]: User named Emily Clark from Finance department accessed the resource Cybertees.THM/contact.html from the source IP 192.168.1.4 and country ` and the 2nd event line `Japan at: Mon Dec  1 10:13:38 2025` 

That is probably because Splunk is breaking the event after the new line `\n` from the binary OR is must be using some default buffer. (🤔 idk )

(Sidenote: while restarting the Splunk server during Phase 2 of the challenge you will likely see the `Error in savedsearches.conf- Invalid key in stanza`. don't worry it's not causing any issue with the original challenge.)

Answering questions 1 and 2 after viewing inputs.conf file we notice the `source_type` to use for props.conf, i.e `network_logs`

```c
[script:///opt/splunk/etc/apps/fixit/bin/network-logs]

index = main
source = networks
sourcetype = network_logs
interval = 1
```

#### Creating the props.conf File

- Navigate to `/opt/splunk/etc/apps/fixit/local`
- Use text editor to create `props.conf`
- Make Changes 
```c
[network_logs]
BREAK_ONLY_BEFORE = \[Network-log\]:
```
- Paste in the following entry and restart Splunk with `/opt/splunk/bin/splunk restart`

Answer for question 3 - 4 above. (Test the regex with regex101.com and set the option gm for "global, multi line")

---
## Phase 2: Extracting Custom Fields

*The next phase of your challenge requires the extraction of meaningful fields from your client's event data. You can accomplish this by updating the Fixit app’s configuration files or by creating field extractions directly through the Splunk UI.*

*Use the sample logs below to help extract the following fields*

- `Username`
- `Department`
- `Domain`
- `URI`
- `SourceIP`
- `Country`


Example logs generated given below. We have to extract the above Custom fields
```c
[Network-log]: User named Emily Clark from Finance department accessed the resource Cybertees.THM/contact.html from the source IP 192.168.1.4 and country 
Japan at: Mon Dec  1 10:13:38 2025
[Network-log]: User named Robert Wilson from HR department accessed the resource Cybertees.THM/signup.html from the source IP 10.0.0.2 and country 
Germany at: Mon Dec  1 10:13:42 2025
[Network-log]: User named Patricia Allen from Finance department accessed the resource Cybertees.THM/checkout.html from the source IP 172.16.0.1 and country 
Mexico at: Mon Dec  1 10:13:48 2025
```

![[Pasted image 20260503004040.png]]

Answer: Tested on [regex101](https://regex101.com)
```c
// Some Regex correction by given by AI
// later removed the Date regex bcz not needed...
[network_custom_fields]
REGEX = \[Network-log\]:\sUser\s+named\s+(\w+\s+\w+)\s+from\s+(\w+)\sdepartment\s+accessed\s+the\s+resource\s+(\S+?)\/(\S+)\s+from\s+the\s+source\s+IP\s+(\d+\.\d+\.\d+\.\d+)\s+and\s+country\s+([A-Za-z\s]+?)\s+at:
FORMAT = User::$1 Department::$2 Domain::$3 URI::$4 SourceIP::$5 Country::$6
```

At the very end of the Notes are the Files Required for custom fields extraction.

---

## Phase 3: Analyzing Event Data

*Once the log data is flowing in correctly and the fields have been extracted, it's time to begin your analysis. Using the available data, apply your skills to uncover what's happening on the network!*

Q: Domain appeared ? : Cybertees.THM
Q: How many `Username` we got ? and who is the Most active User on the network ? :
![[Pasted image 20260504013750.png|500x400]]

Q: How many `URI` fields we got ? and how many individual `/products` pages appear ?:

![[Pasted image 20260504011143.png|500x400]]

Q: What is the only `URI` field value found in the event data without a file extension? : /sales/

Q: How many unique IP ranges are represented in the observed network traffic? 
Answer:  below SPL query gives
```c
index=main
| eval ip_range=replace(SourceIP,"^(\\d+\\.\\d+\\.\\d+)\\.\\d+$","\\1.0/24")
| stats dc(ip_range) AS unique_ip_ranges values(ip_range) AS ip_ranges
```

OUTPUT:
	unique_ip_ranges	: 5
	ip_ranges: 
	10.0.0.0/24
	172.16.0.0/24
	192.168.0.0/24
	192.168.1.0/24
	192.168.2.0/24

There are actually 3 ranges here not 5. 192.168 , 172.16 and 10.0 range. You can fix this SPL Query

Q: Which user accessed the `secret-document.pdf` on your client's server?: 
Answer: (use SPL to search this.)

---
# Config Files created
#### local/fields.conf
```c
[User]
INDEXED = true

[Department]
INDEXED = true

[Domain]
INDEXED = true

[URI]
INDEXED = true

[SourceIP]
INDEXED = true

[Country]
INDEXED = true
```

#### local/props.conf
```c
[network_logs]
SHOULD_LINEMERGE = true
BREAK_ONLY_BEFORE = \[Network-log\]:
TRANSFORMS-custom_fields = network_custom_fields
```


#### local/transforms.conf
```c
[network_custom_fields]
REGEX = \[Network-log\]:\sUser\s+named\s+(\w+\s+\w+)\s+from\s+(\w+)\sdepartment\s+accessed\s+the\s+resource\s+(\S+?)\/(\S+)\s+from\s+the\s+source\s+IP\s+(\d+\.\d+\.\d+\.\d+)\s+and\s+country\s+([A-Za-z\s]+?)\s+at:
FORMAT = User::$1 Department::$2 Domain::$3 URI::$4 SourceIP::$5 Country::$6
WRITE_META = true
```
