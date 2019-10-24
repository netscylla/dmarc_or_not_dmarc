#!/usr/bin/env python3

import sys

if sys.version_info < (3,0):
    print("ERROR: some run message")
    sys.exit(1)

import argparse
import queue
import threading
import time
import dns.resolver
import re

domain_queue = queue.Queue()
print_queue = queue.Queue()
args = None
global answers

def parse_args():
    parser = argparse.ArgumentParser(description="Threaded script to analyse domains for non-existant or vulnerable dmarc implementations.")
    parser.add_argument("file", type=argparse.FileType('r'), help="Input file containing one domain per line.")
    parser.add_argument("-v", "--verbose", help="Display debug messages.", action="store_true")
    parser.add_argument("-t", "--threads", help="Number of threads to run with. Default is 20", type=int, default=20)
    parser.add_argument("-o", "--output", help="Output file for vulnerable domains only.", type=argparse.FileType('w'))

    return parser.parse_args()

def thread_worker(args):
    while not domain_queue.empty():
        try:
            domain = domain_queue.get()
            if args.verbose:
                print("Accessing dmarc record for "+domain)
            try:
                answers = dns.resolver.query('_dmarc.' + format(domain),'txt')
            except Exception as e:
                print_queue.put(domain)
            if len(answers) > 0:
                if args.verbose:
                    print("Found a dmarc record... "+domain)
                if (re.match(r'\sp=none', str(answers[0]))):
                    if args.verbose:
                        print(domain + " dmarc record in reporting mode only, can still spoof")
                    print_queue.put(domain)
                else:
                    if args.verbose:
                       print(domain + " has hardened dmarc record")
            else:
                print("Something went wrong")
        except Exception as e:
            if args.verbose is not None:
                print("Error: " + str(e))

def print_worker(args):
    if args.output is not None:
        while True:
            toPrint = print_queue.get()
            if toPrint == 'done':
                return
            args.output.write(toPrint + "\n")


def main():
    print("-----------------------------------------------------------")
    print("|                   dmarc or not dmarc                     |")
    print("|                        By Andy                           |")
    print("|                       @netscylla                         |")
    print("-----------------------------------------------------------")
    args = parse_args()
    with args.file as domainFile:
        for line in domainFile:
            domain_queue.put(line.strip())
    if args.verbose:
        print("Records read: " + str(domain_queue.qsize()) )
    threads = []
    start = time.perf_counter()
    for i in range(args.threads):
        t = threading.Thread(target=thread_worker, args=(args,))
        t.daemon = True 
        t.start()
        threads.append(t)

    print_thread = threading.Thread(target=print_worker, args=(args,))
    print_thread.daemon = True
    print_thread.start()

    for t in threads:
        t.join()
    print_queue.put('done')

    print_thread.join()

    print("Done!  Total execution time: ", time.perf_counter() - start, " seconds")

if __name__ == "__main__":
    main()
