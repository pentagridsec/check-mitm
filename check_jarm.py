#!/usr/bin/env python3
#
# -----------------------------------------------------------------------------
# Copyright (c) 2024 Martin Schobert, Pentagrid AG
# Copyright (c) 2020 salesforce.com, inc.
#   originally developed by John Althouse, Andrew Smart, RJ Nunaly, Mike Brady
#   converted to Python by Caleb Yu and published under a BSD 3-Clause license
#   here: https://github.com/salesforce/jarm/blob/master/jarm.py
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

from __future__ import print_function

import codecs
import socket
import struct
import os
import sys
import random
import argparse
import hashlib
import ipaddress
from typing import Union

default_timeout = 20


def choose_grease() -> bytes:
    """
    Get a random GREASE value.
    GREASE stands for Generate Random Extensions And Sustain Extensibility. It is a concept that reserves some dummy
    data values that can be sprinkled into TLS messages and which an implementation should ignore and which allows
    broken implementations to detect their brokeness.
    See  https://datatracker.ietf.org/doc/html/draft-ietf-tls-grease-03.
    :return: Returns a random two-byte value from a list of predefined grease values.
    """
    grease_list = [b"\x0a\x0a", b"\x1a\x1a", b"\x2a\x2a", b"\x3a\x3a", b"\x4a\x4a", b"\x5a\x5a", b"\x6a\x6a",
                   b"\x7a\x7a", b"\x8a\x8a", b"\x9a\x9a", b"\xaa\xaa", b"\xba\xba", b"\xca\xca", b"\xda\xda",
                   b"\xea\xea", b"\xfa\xfa"]
    return random.choice(grease_list)


def build_packet(jarm_details: list[str]) -> bytes:
    """
    Create a TLS Client Hello packet.
    :param jarm_details: An array with TLS client hello parameters used to construct the entire packet.
    :return: Returns a byte-string withe the packet data.
    """
    payload = b"\x16"
    client_hello = None

    # Version Check
    if jarm_details[2] == "TLS_1.3":
        payload += b"\x03\x01"
        client_hello = b"\x03\x03"
    elif jarm_details[2] == "SSLv3":
        payload += b"\x03\x00"
        client_hello = b"\x03\x00"
    elif jarm_details[2] == "TLS_1":
        payload += b"\x03\x01"
        client_hello = b"\x03\x01"
    elif jarm_details[2] == "TLS_1.1":
        payload += b"\x03\x02"
        client_hello = b"\x03\x02"
    elif jarm_details[2] == "TLS_1.2":
        payload += b"\x03\x03"
        client_hello = b"\x03\x03"

    # Random values in client hello
    client_hello += os.urandom(32)
    session_id = os.urandom(32)
    session_id_length = struct.pack(">B", len(session_id))
    client_hello += session_id_length
    client_hello += session_id
    # Get ciphers
    cipher_choice = get_ciphers(jarm_details)
    client_suites_length = struct.pack(">H", len(cipher_choice))
    client_hello += client_suites_length
    client_hello += cipher_choice
    client_hello += b"\x01"  # cipher methods
    client_hello += b"\x00"  # compression_methods
    # Add extensions to client hello
    extensions = get_extensions(jarm_details)
    client_hello += extensions
    # Finish packet assembly
    inner_length = b"\x00"
    inner_length += struct.pack(">H", len(client_hello))
    handshake_protocol = b"\x01"
    handshake_protocol += inner_length
    handshake_protocol += client_hello
    outer_length = struct.pack(">H", len(handshake_protocol))
    payload += outer_length
    payload += handshake_protocol
    return payload


def get_ciphers(jarm_details: list[str]) -> bytes:
    """
    Get list of cipher depending on the JARM request mode.
    :param jarm_details: The JARM configuration as a list of strings.
    :return: Returns a byte-list, which reporesents the client-supported ciphers.
    """
    selected_ciphers = b""
    cipher_list = []

    # Two cipher lists: NO1.3 and ALL
    if jarm_details[3] == "ALL":
        cipher_list = [b"\x00\x16", b"\x00\x33", b"\x00\x67", b"\xc0\x9e", b"\xc0\xa2", b"\x00\x9e", b"\x00\x39",
                       b"\x00\x6b", b"\xc0\x9f", b"\xc0\xa3", b"\x00\x9f", b"\x00\x45", b"\x00\xbe", b"\x00\x88",
                       b"\x00\xc4", b"\x00\x9a", b"\xc0\x08", b"\xc0\x09", b"\xc0\x23", b"\xc0\xac", b"\xc0\xae",
                       b"\xc0\x2b", b"\xc0\x0a", b"\xc0\x24", b"\xc0\xad", b"\xc0\xaf", b"\xc0\x2c", b"\xc0\x72",
                       b"\xc0\x73", b"\xcc\xa9", b"\x13\x02", b"\x13\x01", b"\xcc\x14", b"\xc0\x07", b"\xc0\x12",
                       b"\xc0\x13", b"\xc0\x27", b"\xc0\x2f", b"\xc0\x14", b"\xc0\x28", b"\xc0\x30", b"\xc0\x60",
                       b"\xc0\x61", b"\xc0\x76", b"\xc0\x77", b"\xcc\xa8", b"\x13\x05", b"\x13\x04", b"\x13\x03",
                       b"\xcc\x13", b"\xc0\x11", b"\x00\x0a", b"\x00\x2f", b"\x00\x3c", b"\xc0\x9c", b"\xc0\xa0",
                       b"\x00\x9c", b"\x00\x35", b"\x00\x3d", b"\xc0\x9d", b"\xc0\xa1", b"\x00\x9d", b"\x00\x41",
                       b"\x00\xba", b"\x00\x84", b"\x00\xc0", b"\x00\x07", b"\x00\x04", b"\x00\x05"]
    elif jarm_details[3] == "NO1.3":
        cipher_list = [b"\x00\x16", b"\x00\x33", b"\x00\x67", b"\xc0\x9e", b"\xc0\xa2", b"\x00\x9e", b"\x00\x39",
                       b"\x00\x6b", b"\xc0\x9f", b"\xc0\xa3", b"\x00\x9f", b"\x00\x45", b"\x00\xbe", b"\x00\x88",
                       b"\x00\xc4", b"\x00\x9a", b"\xc0\x08", b"\xc0\x09", b"\xc0\x23", b"\xc0\xac", b"\xc0\xae",
                       b"\xc0\x2b", b"\xc0\x0a", b"\xc0\x24", b"\xc0\xad", b"\xc0\xaf", b"\xc0\x2c", b"\xc0\x72",
                       b"\xc0\x73", b"\xcc\xa9", b"\xcc\x14", b"\xc0\x07", b"\xc0\x12", b"\xc0\x13", b"\xc0\x27",
                       b"\xc0\x2f", b"\xc0\x14", b"\xc0\x28", b"\xc0\x30", b"\xc0\x60", b"\xc0\x61", b"\xc0\x76",
                       b"\xc0\x77", b"\xcc\xa8", b"\xcc\x13", b"\xc0\x11", b"\x00\x0a", b"\x00\x2f", b"\x00\x3c",
                       b"\xc0\x9c", b"\xc0\xa0", b"\x00\x9c", b"\x00\x35", b"\x00\x3d", b"\xc0\x9d", b"\xc0\xa1",
                       b"\x00\x9d", b"\x00\x41", b"\x00\xba", b"\x00\x84", b"\x00\xc0", b"\x00\x07", b"\x00\x04",
                       b"\x00\x05"]
    # Change cipher order
    if jarm_details[4] != "FORWARD":
        cipher_list = mung_cipher(cipher_list, jarm_details[4])
    # Add GREASE to beginning of cipher list (if applicable)
    if jarm_details[5] == "GREASE":
        cipher_list.insert(0, choose_grease())
    # Generate cipher list
    for cipher in cipher_list:
        selected_ciphers += cipher
    return selected_ciphers


def mung_cipher(ciphers: list[bytes], request: str) -> list[bytes]:
    """
    Mix the list of cipher bytes.
    :param ciphers: Input list of cipher bytes.
    :param request: A string indicating the operation, which is "REVERSE", "BOTTOM_HALF", "TOP_HALF", "MIDDLE_OUT".
    :return: Returns a byte-list, which reporesents the client-supported ciphers.
    """
    output = []
    cipher_len = len(ciphers)
    # Ciphers backward
    if request == "REVERSE":
        output = ciphers[::-1]
    # Bottom half of ciphers
    elif request == "BOTTOM_HALF":
        if cipher_len % 2 == 1:
            output = ciphers[int(cipher_len/2)+1:]
        else:
            output = ciphers[int(cipher_len/2):]
    # Top half of ciphers in reverse order
    elif request == "TOP_HALF":
        if cipher_len % 2 == 1:
            output.append(ciphers[int(cipher_len/2)])
            # Top half gets the middle cipher
        output += mung_cipher(mung_cipher(ciphers, "REVERSE"), "BOTTOM_HALF")
    # Middle-out cipher order
    elif request == "MIDDLE_OUT":
        middle = int(cipher_len/2)
        # if ciphers are uneven, start with the center.  Second half before first half
        if cipher_len % 2 == 1:
            output.append(ciphers[middle])
            for i in range(1, middle+1):
                output.append(ciphers[middle + i])
                output.append(ciphers[middle - i])
        else:
            for i in range(1, middle+1):
                output.append(ciphers[middle-1 + i])
                output.append(ciphers[middle - i])
    return output


def get_extensions(jarm_details: list[str]) -> bytes:
    """
    Creates extensions for the handshake.
    :param jarm_details: The JARM configuration as a list of strings.
    :return: Returns a byte-list with the TLS extensions.
    """
    extension_bytes = b""
    all_extensions = b""
    grease = False
    # GREASE
    if jarm_details[5] == "GREASE":
        all_extensions += choose_grease()
        all_extensions += b"\x00\x00"
        grease = True

    # Server name
    all_extensions += create_extension_sni(jarm_details[0])

    # Other extensions
    extended_master_secret = b"\x00\x17\x00\x00"
    all_extensions += extended_master_secret
    max_fragment_length = b"\x00\x01\x00\x01\x01"
    all_extensions += max_fragment_length
    renegotiation_info = b"\xff\x01\x00\x01\x00"
    all_extensions += renegotiation_info
    supported_groups = b"\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19"
    all_extensions += supported_groups
    ec_point_formats = b"\x00\x0b\x00\x02\x01\x00"
    all_extensions += ec_point_formats
    session_ticket = b"\x00\x23\x00\x00"
    all_extensions += session_ticket

    # Application Layer Protocol Negotiation extension
    all_extensions += create_extension_apln(jarm_details)
    signature_algorithms = b"\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01"
    all_extensions += signature_algorithms

    # Key share extension
    all_extensions += create_extension_key_share(grease)
    psk_key_exchange_modes = b"\x00\x2d\x00\x02\x01\x01"
    all_extensions += psk_key_exchange_modes

    # Supported versions extension
    if (jarm_details[2] == "TLS_1.3") or (jarm_details[7] == "1.2_SUPPORT"):
        all_extensions += create_extension_supported_versions(jarm_details, grease)
    # Finish assembling extensions
    extension_length = len(all_extensions)
    extension_bytes += struct.pack(">H", extension_length)
    extension_bytes += all_extensions

    return extension_bytes


def create_extension_sni(host: str) -> bytes:
    """
    Create the bytes for a Server Name Indication extension.
    :param host: The hostname to insert into the SNI extension.
    :return: Return byte-list for this extension.
    """
    ext_sni = b"\x00\x00"
    ext_sni_length = len(host)+5
    ext_sni += struct.pack(">H", ext_sni_length)
    ext_sni_length2 = len(host)+3
    ext_sni += struct.pack(">H", ext_sni_length2)
    ext_sni += b"\x00"
    ext_sni_length3 = len(host)
    ext_sni += struct.pack(">H", ext_sni_length3)
    ext_sni += host.encode()
    return ext_sni


def create_extension_apln(jarm_details: list[str]) -> bytes:
    """
    Create the bytes for an Application-Layer Protocol Negotiation (ALPN) extension.
    :param jarm_details: Parameters for the different TLS requests.
    :return: Return byte-list for this extension.
    """
    ext = b"\x00\x10"
    if jarm_details[6] == "RARE_APLN":
        # Removes h2 and http/1.1
        alpns = [b"\x08\x68\x74\x74\x70\x2f\x30\x2e\x39", b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x30",
                 b"\x06\x73\x70\x64\x79\x2f\x31", b"\x06\x73\x70\x64\x79\x2f\x32", b"\x06\x73\x70\x64\x79\x2f\x33",
                 b"\x03\x68\x32\x63", b"\x02\x68\x71"]
    else:
        # All apln extensions in order from weakest to strongest
        alpns = [b"\x08\x68\x74\x74\x70\x2f\x30\x2e\x39", b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x30",
                 b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x31", b"\x06\x73\x70\x64\x79\x2f\x31",
                 b"\x06\x73\x70\x64\x79\x2f\x32", b"\x06\x73\x70\x64\x79\x2f\x33", b"\x02\x68\x32",
                 b"\x03\x68\x32\x63", b"\x02\x68\x71"]
    # apln extensions can be reordered
    if jarm_details[8] != "FORWARD":
        alpns = mung_cipher(alpns, jarm_details[8])
    all_alpns = b""
    for alpn in alpns:
        all_alpns += alpn
    second_length = len(all_alpns)
    first_length = second_length+2
    ext += struct.pack(">H", first_length)
    ext += struct.pack(">H", second_length)
    ext += all_alpns
    return ext


def create_extension_key_share(grease: bool) -> bytes:
    """
    Create the bytes for an Key Share extension.
    The "key_share" extension contains the endpoint's cryptographic
    parameters. See https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8

    :param grease: Boolean value to indicate if GREASE values should be used as well.
    :return: Return byte-list for this extension.
    """
    ext = b"\x00\x33"
    # Add grease value if necessary
    if grease:
        share_ext = choose_grease()
        share_ext += b"\x00\x01\x00"
    else:
        share_ext = b""
    group = b"\x00\x1d"
    share_ext += group
    key_exchange_length = b"\x00\x20"
    share_ext += key_exchange_length
    share_ext += os.urandom(32)
    second_length = len(share_ext)
    first_length = second_length+2
    ext += struct.pack(">H", first_length)
    ext += struct.pack(">H", second_length)
    ext += share_ext
    return ext


def create_extension_supported_versions(jarm_details: list[str], grease: bool) -> bytes:
    """
    Create an extension entry to indicate which TLS versions the client supports.
    See https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.1.
    :param jarm_details: Parameters for the different TLS requests.
    :param grease: Boolean value to indicate if GREASE values should be used as well.
    :return: Return byte-list for this extension.
    """
    if jarm_details[7] == "1.2_SUPPORT":
        # TLS 1.3 is not supported
        tls = [b"\x03\x01", b"\x03\x02", b"\x03\x03"]
    else:
        # TLS 1.3 is supported
        tls = [b"\x03\x01", b"\x03\x02", b"\x03\x03", b"\x03\x04"]
    # Change supported version order, by default, the versions are from oldest to newest
    if jarm_details[8] != "FORWARD":
        tls = mung_cipher(tls, jarm_details[8])
    # Assemble the extension
    ext = b"\x00\x2b"
    # Add GREASE if applicable
    if grease:
        versions = choose_grease()
    else:
        versions = b""
    for version in tls:
        versions += version
    second_length = len(versions)
    first_length = second_length+1
    ext += struct.pack(">H", first_length)
    ext += struct.pack(">B", second_length)
    ext += versions
    return ext


def send_packet(packet: bytes, host: Union[ipaddress.IPv4Address, ipaddress.IPv6Address], destination_port: int,
                socks5_host: str, socks5_port: int):
    """
    Send a (Client Hello) packet to a destination host.
    :param packet: The payload to send. It is a byte-list and contains the Client Hello.
    :param host: The host to connect. It is an IPv4Address or IPv6Address object.
    :param destination_port: Connect to the host at this port number.
    :param socks5_host: Hostname or string with IP address of the SOCKS5 proxy. A Python-true value enables proxy usage.
    :param socks5_port: The corresponding proxy port.
    :return: Returns the received bytes, which contain the Server Hello
    """

    # If whe should use a proxy, we try to import the Python proxy module and otherwise not
    # to avoid a dependency.
    if socks5_host:
        try:
            import socks
        except ImportError:
            print('ERROR: Proxy option requires PySocks module. Install with: pip install PySocks or via package manager.')
            sys.exit(3)

    # Connect the socket
    if type(ipaddress.ip_address(host)) == ipaddress.IPv6Address:
        if socks5_host:
            sock = socks.socksocket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.set_proxy(socks.SOCKS5, socks5_host, socks5_port)
        else:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

        sock.connect((str(host), destination_port, 0, 0))

    elif type(ipaddress.ip_address(host)) == ipaddress.IPv4Address:
        if socks5_host:
            sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            sock.set_proxy(socks.SOCKS5, socks5_host, socks5_port)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((str(host), destination_port))
    else:
        raise RuntimeError("Unexpected data type for destination host.")

    sock.settimeout(default_timeout)

    sock.sendall(packet)

    # Receive server hello
    data = sock.recv(1484)

    # Close socket
    sock.shutdown(socket.SHUT_RDWR)
    sock.close()

    return bytearray(data)


def parse_received_packet(data: bytes) -> str:
    """
    If a Server Hello packet is received, decipher the details and return them in a stringified version.
    Parsing errors are catched.
    :param data: Server Hello data as byte-list.
    :return: Returns a string-version of the results.
    """
    try:
        if data is None:
            return "|||"
        jarm = ""

        # Server Hello error
        if data[0] == 21:
            return "|||"

        # Check for Server Hello
        elif (data[0] == 22) and (data[5] == 2):
            counter = data[43]
            # Find server's selected cipher
            selected_cipher = data[counter+44:counter+46]
            # Find server's selected version
            version = data[9:11]
            # Format
            jarm += codecs.encode(selected_cipher, 'hex').decode('ascii')
            jarm += "|"
            jarm += codecs.encode(version, 'hex').decode('ascii')
            jarm += "|"

            # Extract extensions
            server_hello_length = int.from_bytes(data[3:5], "big")
            extensions = (extract_extension_info(data, counter, server_hello_length))
            jarm += extensions

            return jarm
        else:
            return "|||"

    except Exception:
        return "|||"


def extract_extension_info(data: bytes, counter: int, server_hello_length: int) -> str:
    """
    Extract the extensions and their values from the Server Hello.
    Parsing errors are catched.
    :param data: The entire Server Hello data as byte-list.
    :param counter: Number of the extension to extract.
    :param server_hello_length: Length of the Server Hello packet.
    :return: Returns a string-version of the supported extensions.
    """
    try:
        # Error handling
        if data[counter+47] == 11:
            return "|"
        elif (data[counter+50:counter+53] == b"\x0e\xac\x0b") or (data[82:85] == b"\x0f\xf0\x0b"):
            return "|"
        elif counter+42 >= server_hello_length:
            return "|"
        count = 49+counter
        length = int(codecs.encode(data[counter+47:counter+49], 'hex'), 16)
        maximum = length+(count-1)
        types = []
        values = []

        # Collect all extension types and values for later reference
        while count < maximum:
            types.append(data[count:count+2])
            ext_length = int(codecs.encode(data[count+2:count+4], 'hex'), 16)
            if ext_length == 0:
                count += 4
                values.append("")
            else:
                values.append(data[count+4:count+4+ext_length])
                count += ext_length+4
        result = ""

        # Read application_layer_protocol_negotiation
        alpn = extract_data_from_extension(b"\x00\x10", types, values)
        result += str(alpn)
        result += "|"

        # Add formating hyphens
        add_hyphen = 0
        while add_hyphen < len(types):
            result += codecs.encode(types[add_hyphen], 'hex').decode('ascii')
            add_hyphen += 1
            if add_hyphen == len(types):
                break
            else:
                result += "-"
        return result

    # Error handling
    except IndexError:
        result = "|"
        return result


def extract_data_from_extension(ext_type: bytes, types: list[bytes], values: list[bytes]) -> str:
    """
    Find an extension identified by ext_type and extract data.
    :param ext_type: Find this extention identified by a byte-list.
    :param types: The extension types as a list.
    :param values: The extension values as a list.
    :return: Return extracted data as string, for example ASCII or hex.
    """
    i = 0
    # For the APLN extension, grab the value in ASCII
    if ext_type == b"\x00\x10":
        while i < len(types):
            if types[i] == ext_type:
                return (values[i][3:]).decode()
            i += 1
    else:
        while i < len(types):
            if types[i] == ext_type:
                return values[i].hex()
            i += 1
    return ""


def calc_jarm_hash(jarm_raw: str) -> str:
    """
    Calculate the JARM hash over the input and return it as SHA256 hash.
    :param jarm_raw: String-input with the data.
    :return: Returns a string with a JARM hash.
    """
    # If jarm is empty, 62 zeros for the hash
    if jarm_raw == "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||":
        return "0"*62
    fuzzy_hash = ""
    handshakes = jarm_raw.split(",")
    alpns_and_ext = ""
    for handshake in handshakes:
        components = handshake.split("|")
        # Custom jarm hash includes a fuzzy hash of the ciphers and versions
        fuzzy_hash += get_cipher_info(components[0])
        fuzzy_hash += get_version_info(components[1])
        alpns_and_ext += components[2]
        alpns_and_ext += components[3]

    # Custom jarm hash has the sha256 of alpns and extensions added to the end
    sha256 = (hashlib.sha256(alpns_and_ext.encode())).hexdigest()
    fuzzy_hash += sha256[0:32]
    return fuzzy_hash


def get_cipher_info(cipher_num: str) -> str:
    """
    Returns the cipher number for the
    Fuzzy hash for ciphers is the index number (in hex) of the cipher in the list
    :param cipher_num: The cipher number as hex-string like, C02F (in hex).
    :return: Returns a string indicating cipher numbers.
    """

    if cipher_num == "":
        return "00"

    cipher_list = [b"\x00\x04", b"\x00\x05", b"\x00\x07", b"\x00\x0a", b"\x00\x16", b"\x00\x2f", b"\x00\x33",
                   b"\x00\x35", b"\x00\x39", b"\x00\x3c", b"\x00\x3d", b"\x00\x41", b"\x00\x45", b"\x00\x67",
                   b"\x00\x6b", b"\x00\x84", b"\x00\x88", b"\x00\x9a", b"\x00\x9c", b"\x00\x9d", b"\x00\x9e",
                   b"\x00\x9f", b"\x00\xba", b"\x00\xbe", b"\x00\xc0", b"\x00\xc4", b"\xc0\x07", b"\xc0\x08",
                   b"\xc0\x09", b"\xc0\x0a", b"\xc0\x11", b"\xc0\x12", b"\xc0\x13", b"\xc0\x14", b"\xc0\x23",
                   b"\xc0\x24", b"\xc0\x27", b"\xc0\x28", b"\xc0\x2b", b"\xc0\x2c", b"\xc0\x2f", b"\xc0\x30",
                   b"\xc0\x60", b"\xc0\x61", b"\xc0\x72", b"\xc0\x73", b"\xc0\x76", b"\xc0\x77", b"\xc0\x9c",
                   b"\xc0\x9d", b"\xc0\x9e", b"\xc0\x9f", b"\xc0\xa0", b"\xc0\xa1", b"\xc0\xa2", b"\xc0\xa3",
                   b"\xc0\xac", b"\xc0\xad", b"\xc0\xae", b"\xc0\xaf", b'\xcc\x13', b'\xcc\x14', b'\xcc\xa8',
                   b'\xcc\xa9', b'\x13\x01', b'\x13\x02', b'\x13\x03', b'\x13\x04', b'\x13\x05']
    list_as_hex = ["%04X" % int.from_bytes(b, "big") for b in cipher_list]
    idx = list_as_hex.index(cipher_num.upper())
    hexvalue = "%X" % (idx + 1)

    # This part must always be two bytes
    if len(hexvalue) < 2:
        return "0" + hexvalue
    else:
        return hexvalue


def get_version_info(version: str) -> str:
    """
    This captures a single version byte based on version.
    :param version: version information.
    :return: Returns a single-character string for the TLS version.
    """
    if version == "":
        return "0"
    return "abcdef"[int(version[3:4])]


def scan_host(destination_host, destination_address, destination_port, socks5_host, socks5_port):

    # Select the packets and formats to send
    # Array format = [destination_host,destination_port,version,cipher_list,cipher_order,GREASE,RARE_APLN,1.3_SUPPORT,extension_orders]

    tls1_2_forward = [destination_host, destination_port, "TLS_1.2", "ALL", "FORWARD", "NO_GREASE", "APLN", "1.2_SUPPORT", "REVERSE"]
    tls1_2_reverse = [destination_host, destination_port, "TLS_1.2", "ALL", "REVERSE", "NO_GREASE", "APLN", "1.2_SUPPORT", "FORWARD"]
    tls1_2_top_half = [destination_host, destination_port, "TLS_1.2", "ALL", "TOP_HALF", "NO_GREASE", "APLN", "NO_SUPPORT", "FORWARD"]
    tls1_2_bottom_half = [destination_host, destination_port, "TLS_1.2", "ALL", "BOTTOM_HALF", "NO_GREASE", "RARE_APLN", "NO_SUPPORT", "FORWARD"]
    tls1_2_middle_out = [destination_host, destination_port, "TLS_1.2", "ALL", "MIDDLE_OUT", "GREASE", "RARE_APLN", "NO_SUPPORT", "REVERSE"]
    tls1_1_middle_out = [destination_host, destination_port, "TLS_1.1", "ALL", "FORWARD", "NO_GREASE", "APLN", "NO_SUPPORT", "FORWARD"]
    tls1_3_forward = [destination_host, destination_port, "TLS_1.3", "ALL", "FORWARD", "NO_GREASE", "APLN", "1.3_SUPPORT", "REVERSE"]
    tls1_3_reverse = [destination_host, destination_port, "TLS_1.3", "ALL", "REVERSE", "NO_GREASE", "APLN", "1.3_SUPPORT", "FORWARD"]
    tls1_3_invalid = [destination_host, destination_port, "TLS_1.3", "NO1.3", "FORWARD", "NO_GREASE", "APLN", "1.3_SUPPORT", "FORWARD"]
    tls1_3_middle_out = [destination_host, destination_port, "TLS_1.3", "ALL", "MIDDLE_OUT", "GREASE", "APLN", "1.3_SUPPORT", "REVERSE"]

    # Possible versions: SSLv3, TLS_1, TLS_1.1, TLS_1.2, TLS_1.3
    # Possible cipher lists: ALL, NO1.3
    # GREASE: either NO_GREASE or GREASE
    # APLN: either APLN or RARE_APLN
    # Supported Verisons extension: 1.2_SUPPPORT, NO_SUPPORT, or 1.3_SUPPORT
    # Possible Extension order: FORWARD, REVERSE
    queue = [tls1_2_forward, tls1_2_reverse, tls1_2_top_half, tls1_2_bottom_half, tls1_2_middle_out, tls1_1_middle_out, tls1_3_forward, tls1_3_reverse, tls1_3_invalid, tls1_3_middle_out]
    jarm = ""

    # Assemble, send, and decipher each packet

    for queue_item in queue:
        payload = build_packet(queue_item)
        server_hello = send_packet(payload, destination_address, destination_port, socks5_host, socks5_port)

        jarm += parse_received_packet(server_hello)

        if queue_item != queue[-1]:
            jarm += ","

    return calc_jarm_hash(jarm)


def main():
    parser = argparse.ArgumentParser(description="Enter an IP address and port to scan.")

    parser.add_argument("--hostname", metavar='HOSTNAME', help="Hostname to use for SNI", required=True)
    parser.add_argument("--target", metavar='IPADDR', help="Enter an IP address to scan.", required=True)
    parser.add_argument("-p", "--port", metavar='PORT', help="Enter a port to scan (default 443).", type=int, default=443)
    parser.add_argument("-v", "--verbose", help="Verbose mode: displays the JARM results before being hashed.",
                        action="store_true")
    parser.add_argument("--expected-hash", metavar='HASH', help="Compare measured hash against expected value.")
    parser.add_argument('--show', help='Just show the value', action='store_true', default=False)
    parser.add_argument("--socks5-host", metavar="PROXYHOST", help="SOCKS5 proxy hostname")
    parser.add_argument("--socks5-port", metavar="PROXYPORT", help="SOCKS5 proxy port", type=int)
    args = parser.parse_args()

    result = scan_host(args.hostname, ipaddress.ip_address(args.target), args.port, args.socks5_host, args.socks5_port)

    if args.show or not args.expected_hash:
        print("JARM: " + result)
        sys.exit(1)

    if args.expected_hash:
        if args.expected_hash == result:
            print(f"OK: Expected hash found for host {args.target}.")
            sys.exit(0)
        else:
            print(f"CRITICAL: Expected hash {args.expected_hash} differs from measured hash {result} for host {args.target}.")
            sys.exit(1)


if __name__ == '__main__':
    main()
