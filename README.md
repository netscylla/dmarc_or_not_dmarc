# dmarc_or_not_dmarc

## Usage
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

@netscylla
