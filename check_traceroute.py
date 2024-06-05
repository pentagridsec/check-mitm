#!/usr/bin/env python3
#
# -----------------------------------------------------------------------------
# Copyright (c) 2024 Martin Schobert, Pentagrid AG
#
# All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 3. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
#  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
#  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
#  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# -----------------------------------------------------------------------------

import argparse
import sys
from ipaddress import IPv4Address, IPv6Address, ip_address
import configparser
from typing import Optional, Union

from scapy.layers.inet6 import IPv6, ICMPv6DestUnreach, ICMPv6TimeExceeded, ICMPv6EchoReply

from scapy.layers.inet import IP, TCP, ICMP
from scapy.sendrecv import sr1
from scapy.volatile import RandShort, RandInt

minttl = 1
maxttl = 30


def l4_traceroute(target: Union[IPv4Address, IPv6Address], _dport: int, timeout: int, last_n: Optional[int] = None) -> \
        list[Union[IPv4Address, IPv6Address]]:
    """
    A layer-4 TCP traceroute.
    :param target: The target host passed as IP address object (IPv4Address or IPv6Address).
    :param _dport: The destination port to use
    :param timeout: A timeout value.
    :param last_n: When returning a list of hops, how many should be returned. Leave value to None for the entire list.
    :return: Returns a list of IP addresses.
    """

    hops = []

    for ttl in range(minttl, maxttl):

        if type(target) == IPv4Address:
            r = sr1(IP(dst=str(target), ttl=ttl) / TCP(seq=RandInt(), sport=RandShort(), dport=_dport), timeout=timeout,
                    verbose=0)
        else:
            r = sr1(IPv6(dst=str(target), hlim=ttl) / TCP(seq=RandInt(), sport=RandShort(), dport=_dport),
                    timeout=timeout, verbose=0)

        if r and (r.haslayer(ICMP) or r.haslayer(ICMPv6DestUnreach) or r.haslayer(ICMPv6TimeExceeded) or r.haslayer(
                ICMPv6EchoReply)):
            ip_addr = ip_address(r.src)
            hops.append(ip_addr)

        if r and r.haslayer(TCP):
            ip_addr = ip_address(r.src)

            if ip_addr == target:
                hops.append(ip_addr)
                break

    if last_n:
        return hops[-last_n:]
    else:
        return hops


def host_list_to_str(hostlist: list[Union[IPv4Address, IPv6Address]]) -> str:
    return ', '.join([str(addr) for addr in hostlist])


def read_last_hops_config(filename: str, hostname: str) -> list[list[Union[IPv4Address, IPv6Address]]]:
    list_of_lists = []

    config = configparser.ConfigParser()
    config.read(filename)
    for key in config[hostname]:
        expected_last_hops = [ip_address(addr) for addr in config[hostname][key].split()]
        list_of_lists.append(expected_last_hops)

    return list_of_lists


def setup_seccomp() -> None:
    """
    Enable SECCOMP filtering.
    """

    try:
        from seccomp import SyscallFilter, KILL_PROCESS, LOG, Attr, ALLOW

        # create a filter object with a default KILL action
        f = SyscallFilter(defaction=KILL_PROCESS)

        f.set_attr(Attr.CTL_LOG, 1)

        allowed_syscalls = [
            "write", "newfstatat", "ioctl", "openat", "lseek", "read", "close", "socket", "setsockopt", "bind",
            "pselect6", "getsockname", "pipe2", "sendto", "brk", "recvmsg", "rt_sigaction", "munmap", "futex", "exit",
            "madvise", "rt_sigprocmask", "exit_group"
        ]

        for sc in allowed_syscalls:
            f.add_rule(ALLOW, sc)

        f.load()

    except ImportError:
        print("ERROR: Failed to use SECCOMP. The module is missing.")
        sys.exit(3)

def drop_caps() -> None:
    """
    Drop capabilities.
    """
    try:
        import _capng as capng
        capng.capng_clear(capng.CAPNG_SELECT_BOTH)
        capng.capng_updatev(capng.CAPNG_ADD, capng.CAPNG_EFFECTIVE | capng.CAPNG_PERMITTED,
                            capng.CAP_NET_RAW, -1)
        capng.capng_apply(capng.CAPNG_SELECT_BOTH)

    except ImportError:
        print("ERROR: Failed to use CAP-NG. The module is missing.")
        sys.exit(3)


def main():
    expected_last_hops = []

    parser = argparse.ArgumentParser(prog="check_traceroute.py",
                                     description='Check the last hops of a traceroute for a set of TCP ports and '
                                                 'compare it to a stored value.')

    parser.add_argument('--verbose', help='Show more logging', action='store_true', default=False)
    parser.add_argument('--target', metavar='IPADDR', type=str, help='IP address to check', required=True)
    parser.add_argument('--show', help='Just show the traceroute', action='store_true', default=False)
    parser.add_argument('--disable-seccomp', help='Disable SECCOMP', action='store_true', default=False)
    parser.add_argument('--disable-cap-dropping', help='Disable CAP-NG and do not drop POSIX capabilities', action='store_true', default=False)

    parser.add_argument('--ports', metavar='PORTS', type=int, nargs='+', required=True, action='append',
                        help='List of destination ports to use for TCP traceroute.')
    parser.add_argument('--last-hops-config', metavar='FILE', type=str,
                        help='A configuration file with a set of last hops.')
    parser.add_argument('--last-hops', metavar='IP_ADDRS', type=str, nargs='+',
                        help='A list of IP addresses that are last hops (overrides config).')
    parser.add_argument('--timeout', metavar='SECONDS', type=int, help='A timeout value in second (default: 3)',
                        default=3)

    args = parser.parse_args()

    if not args.disable_cap_dropping:
        drop_caps()
        if args.verbose:
            print(f"+ Dropping POSIX capabilities using CAP-NG.")

    if not args.disable_seccomp:
        setup_seccomp()
        if args.verbose:
            print(f"+ Enabled SECCOMP.")

    if args.show:
        hops = l4_traceroute(ip_address(args.target), args.ports, args.timeout)
        print(f"+ Hops are: {host_list_to_str(hops)}")
        sys.exit(3)

    if args.last_hops_config:
        # read last hops from config file
        expected_last_hops = read_last_hops_config(args.last_hops_config, args.target)
        if not expected_last_hops:
            print("+ Error reading config entries.")
            sys.exit(3)

    if args.last_hops:
        expected_last_hops = [args.last_hops]  # only allows a single path to destination

    for port in args.ports:

        a_path_is_ok = False

        if args.verbose:
            print(f"+ Testing traceroute to {args.target}:{port}.")

        hops = l4_traceroute(ip_address(args.target), port, args.timeout)

        for alternative_path in expected_last_hops:

            if args.verbose:
                print(f"  + Comparing traceroute for {args.target}:{port} against expected hops " +
                      host_list_to_str(alternative_path) + ".")

            for exp_hop, hop in zip(alternative_path, hops[-len(alternative_path):]):

                if args.verbose:
                    print(f"    + Comparing hop {exp_hop} against {hop}.")

                if exp_hop != hop:
                    print(f"+ Traceroute differs for {args.target}:{port}: " +
                          host_list_to_str(alternative_path) + " vs. last of " + host_list_to_str(hops) +
                          ". I am going to check for a known alternative path.")
                    break

            a_path_is_ok = True

        if not a_path_is_ok:
            print(f"CRITICAL: Traceroute(s) differs for all known paths to {args.target}:{port}.")
            sys.exit(2)

    print(f"OK: Traceroute(s) for {args.target} follow the expected hops for all tested ports.")
    sys.exit(0)


if __name__ == '__main__':
    main()
