#!/usr/bin/env python3

import sys
import argparse
import time
import dns.resolver
import re
import concurrent.futures
try:
    import tqdm
except ModuleNotFoundError:
    tqdm = None


def parse_args():
    parser = argparse.ArgumentParser(
        description="Threaded script to analyse domains for non-existent or vulnerable DMARC implementations.")
    parser.add_argument("file", type=argparse.FileType('r'),
                        help="Input file containing one domain per line.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Display debug messages.")
    parser.add_argument("-t", "--threads", type=int, default=20,
                        help="Number of threads to run with. Default is 20")
    parser.add_argument("-o", "--output", type=argparse.FileType('w'), default=sys.stdout,
                        help="Output file containing one vulnerable domain per line. If omitted, vulnerable domains "
                             "will be output on stdout")

    return parser.parse_args()


def message(m):
    # Using print() as intended, with the newline in the end argument, somehow breaks in a multi-threaded
    # environment - another thread is able to print something between the message and the newline added by print()
    print("{}\n".format(m), end="", file=sys.stderr, flush=True)


def verbose(m):
    if args.verbose:
        message(m)


def error(m):
    message("Error: {}".format(m))


def test_domain_dmarc(domain):
    try:
        verbose("[{}] Querying DMARC record ... ".format(domain))
        try:
            answers = dns.resolver.query('_dmarc.' + format(domain), 'txt')
        except dns.exception.DNSException:
            return domain
        if len(answers) > 0:
            verbose("[{}] Found a DMARC record ...".format(domain))
            if re.match(r'\sp=none', str(answers[0])):
                verbose("[{}] DMARC record is in reporting mode only, can still spoof".format(domain))
                return domain
            else:
                verbose("[{}] DMARC record is hardened".format(domain))
        else:
            error("dns.resolver.query returned 0 answers")
    except Exception as e:
        error(e)


def progressbar(it, **kwargs):
    if args.verbose or not tqdm:
        return it
    else:
        return tqdm.tqdm(it, **kwargs)


if __name__ == "__main__":
    print("-----------------------------------------------------------")
    print("|                   dmarc or not dmarc                     |")
    print("|                        By Andy                           |")
    print("|                       @netscylla                         |")
    print("-----------------------------------------------------------")
    args = parse_args()

    with args.file as domainFile:
        domains = list(map(str.strip, domainFile))
    verbose("Records read: {}".format(len(domains)))

    start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor, args.output as out_file:
        for result in progressbar(
                (
                        f.result()
                        for f in
                        concurrent.futures.as_completed(
                            executor.submit(test_domain_dmarc, domain)
                            for domain in
                            domains
                        )
                ),
                total=len(domains)
        ):
            if result:
                out_file.write(result + "\n")
                out_file.flush()
    print("Done!  Total execution time: ", time.perf_counter() - start, " seconds")
