# dmarc_or_not_dmarc

## What is DMARC 

It stands for “Domain-based Message Authentication, Reporting & Conformance”, is an email authentication, policy, and reporting protocol.

DMARC enables domain owners to advise recipient mail servers of policy decisions that should be made when handling inbound emails claiming to come from the owner’s domain. Specifically, domain owners can request that recipients:
 * allow, quarantine or reject emails that fail SPF and/or DKIM verification
 * collect statistics and notify the domain owner of emails falsely claiming to be from their domain
 * notify the domain owner how many emails are passing and failing email authentication checks
 * send the domain owner data extracted from a failed email, such as header information and web addresses from the email body.
Notifications and statistics resulting from DMARC are sent as aggregate reports and forensic reports:
 * aggregate reports provide regular high level information about emails, such as which Internet Protocol (IP) address they come from and if they failed SPF and DKIM verification
 * forensic reports are sent in real time and provide detailed information on why a particular email failed verification, along with content such as email headers, attachments and web addresses in the body of the email.

## Why dmarc_or_not_dmarc

Netscylla created a quick python program that could utilise threads and could quickly assess dmarc records en-masse.  By importing the Alexa Top 100 or 1000 we can
quickly enumerate hundreds of domains in seconds, to determine which domains have weak or strong dmarc implementations.

This script is to raise awareness of dmarc implementations and the security benefits as laid out in a recent blog article:
 * https://www.netscylla.com/blog/2019/09/03/Prevent-Phishing-with-DMARC.html

# Usage
The script is actually really basic and easy to use.  You make a file of the emails you want to see are valid or not and pass it as an argument to the script:

```
   usage: dmarc_or_not_dmarc.py [-h] [-v] [-t THREADS] [-o OUTPUT] file
   
   Threaded script to analyse domains for non-existant or vulnerable dmarc
   implementations.

   positional arguments:
     file                  Input file containing one domain per line
   
   optional arguments:
     -h, --help            show this help message and exit
     -v, --verbose         Display each result as valid/invalid. By default only
                           displays valid
     -t THREADS, --threads THREADS
                           Number of threads to run with. Default is 20
     -o OUTPUT, --output OUTPUT
                           Output file for vulnerable domains only
```                            

## Author
Andy @ netscylla
Peter @ peshev
@netscylla
@peshev
