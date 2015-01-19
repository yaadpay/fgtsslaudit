#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
"""
Fortinet FortiGate SSL audit - SSL settings audit from a FortiOS show full-configuration.
Decent console terminal that supports ANSI is advised.
Windows users could use conemu.

Usage: python ./fgtsslaudit.py fgt.conf

Further info:
Francois Ropert - https://packetfault.org
"""
__version__ = '0.1'

import sys
import re
from time import gmtime, strftime


def audit(data, vdom):
    """SSL/TLS audit and report."""
    sslvpn = False
    webgui = False
    ssloffload = False
    voip = False
    chupacabra = ""
    if vdom:
        if vdom == "config global":
            vdom_header = "config global\n"
            vdom_footer = "\nend\n"
        else:
            vdom_header = "config vdom\nedit " + vdom + "\n"
            vdom_footer = "\nend\n"
    else:
        vdom_header = ""
        vdom_footer = ""
    # SSL VPN
    if "config vpn ssl settings" in data:
        if "set sslv2 enable" in data:
            chupacabra = "SSLv2 enabled in SSL VPN settings"
            suggestion = "config vpn ssl settings\nset sslv2 disable\nend"
            sslvpn = True
        if "set sslv3 enable" in data:
            chupacabra = "SSLv3 enabled in SSL VPN settings"
            suggestion = "config vpn ssl settings\nset sslv3 disable\nend"
            sslvpn = True
        if "set algorithm low" in data:
            chupacabra = "Low algorithms including those less than 128 bits is enabled in SSL VPN settings"
            suggestion = "config vpn ssl settings\nset algorithm default\nend"
            sslvpn = True
    # Web GUI
    if "config system global" in data:
        for entry in data:
            p=re.compile(r'set admin-https-ssl-versions.*sslv3.*')
            if p.findall(entry):
                chupacabra = "SSLv3 is enabled to access the Web GUI"
                suggestion = "config system global\nset admin-https-ssl-versions tlsv1-1 tlsv1-2\nend"
                webgui = True
            p=re.compile(r'set admin-https-ssl-versions.*tlsv1-0.*')
            if p.findall(entry):
                chupacabra = "TLSv1.0 is enabled to access the Web GUI"
                suggestion = "FOS 5.2.2 minimum is required.\nThe WebGUI is not impacted by POODLE TLS however it is suggested to use at least TLS v1.1 as a best practice.\nconfig system global\nset admin-https-ssl-versions tlsv1-1 tlsv1-2\nend"
                webgui = True
            p=re.compile(r'set gui-https-tls-version.*tlsv1-0.*')
            if p.findall(entry):
                chupacabra = "TLSv1.0 is enabled to access the Web GUI"
                suggestion = "FOS 5.2.2 minimum is required.\nThe WebGUI is not impacted by POODLE TLS however it is suggested to use at least TLS v1.1 as a best practice.\nconfig system global\nset gui-https-tls-versions tlsv1-1 tlsv1-2\nend"
                webgui = True
        if "set strong-crypto disable" in data:
            chupacabra_webgui = "SSLv2/SSLv3 and ciphers weaker than DHE-RSA-AES256-SHA:AES256-SHA / DHE-RSA-AES128-SHA:AES128-SHA / DHE-RSA-AES256-SHA256:AES256-SHA256 / DHE-RSA-AES128-SHA256:AES128-SHA256 may be used to access the Web GUI when strong crypto is disabled"
            suggestion = "config system global\nset strong-crypto enable\nend"
            webgui = True
    # SSL offload
    if "config firewall vip" in data:
        if "set ssl-min-version ssl-3.0" in data:
            chupacabra = "SSLv3 enabled in SSL offload settings"
            suggestion = "config firewall vip\n" + data[data.index('config firewall vip') + 1] + "\nset ssl-min-version tls-1.1\nend\nend"
            ssloffload = True
        if "set ssl-min-version tls-1.0" in data:
            chupacabra = "TLSv1.0 minimum enabled in SSL offload settings"
            suggestion = "Upgrade to FOS 5.0.11 or 5.2.3 is advised for FortiGate with CP processors."
            ssloffload = True
        if "set ssl-max-version tls-1.0" in data:
            chupacabra = "TLSv1.0 maximum enabled in SSL offload settings"
            suggestion = "Upgrade to FOS 5.0.11 or 5.2.3 is advised for FortiGate with CP processors."
            ssloffload = True
        if "set ssl-max-version ssl-3.0" in data:
            chupacabra = "SSLv3 maximum enabled in SSL offload settings"
            suggestion = "config firewall vip\n" + data[data.index('config firewall vip') + 1] + "\nset ssl-max-version tls-1.2\nend\nend"
            ssloffload = True
        for entry in data:
            p=re.compile(r'set ssl-dh-bits.*(768|1024|1536).*')
            if p.findall(entry):
                chupacabra = "AES DH prime lower than 2048 bits is used"
                suggestion = "config firewall vip\n" + data[data.index('config firewall vip') + 1] + "\nset ssl-dh-bits 2048\nend\nend"
                ssloffload = True
        if "set ssl-algorithm low" in data:
            chupacabra = "DES ciphers are allowed in SSL offload settings"
            suggestion = "config firewall vip\n" + data[data.index('config firewall vip') + 1] + "\nset ssl-algorithm high\nend\nend"
            ssloffload = True
        if "set ssl-algorithm medium" in data:
            chupacabra = "RC4 and DES ciphers are allowed in SSL offload settings"
            suggestion = "config firewall vip\n" + data[data.index('config firewall vip') + 1] + "\nset ssl-algorithm high\nend\nend"
            ssloffload = True
        if "config ssl-cipher-suites" in data:
            for entry in data:
                p=re.compile(r'set versions.*ssl-3.0.*')
                if p.findall(entry):
                    chupacabra = "SSLv3.0 configured in SSL offload cipher suite settings"
                    suggestion = "Suggest to use TLSv1.2 and one of the associated ciphers as a best practice.\nconfig firewall vip\n" + data[data.index('config firewall vip') + 1] + "\nconfig ssl-cipher-suites\n" + data[data.index('config ssl-cipher-suites') + 1] + "\nset versions tls-1.2\nset cipher TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256\nset cipher TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256\nset cipher TLS-DHE-RSA-WITH-AES-128-GCM-SHA256\nset cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384\nset cipher TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256\nset cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384\nset cipher TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256\nset cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384\nset cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256\nset cipher TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384\nset cipher TLS-RSA-WITH-AES-128-GCM-SHA256\nset cipher TLS-RSA-WITH-AES-256-GCM-SHA384\nend\nend"
                    ssloffload = True
                p=re.compile(r'set versions.*tls-1.0.*')
                if p.findall(entry):
                    chupacabra = "TLSv1.0 configured in SSL offload cipher suite settings"
                    suggestion = "Suggest to use TLSv1.1 or TLSv1.2 and one of the associated ciphers as a best practice.\nconfig firewall vip\n" + data[data.index('config firewall vip') + 1] + "\nconfig ssl-cipher-suites\n" + data[data.index('config ssl-cipher-suites') + 1] + "\nset versions tls-1.2\nset cipher TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256\nset cipher TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256\nset cipher TLS-DHE-RSA-WITH-AES-128-GCM-SHA256\nset cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384\nset cipher TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256\nset cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384\nset cipher TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256\nset cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384\nset cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256\nset cipher TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384\nset cipher TLS-RSA-WITH-AES-128-GCM-SHA256\nset cipher TLS-RSA-WITH-AES-256-GCM-SHA384\nend\nend"
                    ssloffload = True
                if "set cipher TLS-RSA-WITH-DES-CBC-SHA" in entry:
                    chupacabra = "Weak cipher is configured in custom SSL offload ciphers suite settings"
                    suggestion = "Suggest to delete it if you are not afraid of backward compatibility"
                    ssloffload = True
                if "set cipher TLS-DHE-RSA-WITH-DES-CBC-SHA" in entry:
                    chupacabra = "Weak cipher is configured in custom SSL offload ciphers suite settings"
                    suggestion = "Suggest to delete it if you are not afraid of backward compatibility"
                    ssloffload = True
    # VoIP
    if "config voip profile" in data:
        if "set ssl-min-version ssl-3.0" in data:
            chupacabra = "SSLv3 enabled in " + data[data.index('config voip profile') + 1].split("edit ")[1] + " VoIP profile"
            suggestion = "config voip profile\n" + data[data.index('config voip profile') + 1] + "\nconfig sip" + "\nset ssl-min-version tls-1.1\nend\nend"
            voip = True
        if "set ssl-min-version tls-1.0" in data:
            chupacabra = "TLSv1.0 minimum enabled in " + data[data.index('config voip profile') + 1].split("edit ")[1] + " VoIP profile"
            suggestion = "Upgrade to FOS 5.0.11 or 5.2.3 is advised for FortiGate with CP processors."
            voip = True
        if "set ssl-max-version tls-1.0" in data:
            chupacabra = "TLSv1.0 maximum enabled in " + data[data.index('config voip profile') + 1].split("edit ")[1] + " VoIP profile"
            suggestion = "Upgrade to FOS 5.0.11 or 5.2.3 is advised for FortiGate with CP processors."
            voip = True
        if "set ssl-max-version ssl-3.0" in data:
            chupacabra = "SSLv3 maximum enabled in " + data[data.index('config voip profile') + 1].split("edit ")[1] + " VoIP profile"
            suggestion = "config voip profile\n" + data[data.index('config voip profile') + 1] + "\nconfig sip" + "\nset ssl-max-version tls-1.2\nend\nend"
            voip = True
    # Wan optimization
    if "config wanopt ssl-server" in data:
        if "set ssl-min-version ssl-3.0" in data:
            chupacabra = "SSLv3 enabled in " + data[data.index('config wanopt ssl-server') + 1].split("edit ")[1] + " wanopt SSL profile"
            suggestion = "config wanopt ssl-server\n" + data[data.index('config wanopt ssl-server') + 1] + "\nedit " + data[data.index('config wanopt ssl-server') + 1].split("edit ")[1] + "\nset ssl-min-version tls-1.1\nend\nend"
            wanopt = True
        if "set ssl-min-version tls-1.0" in data:
            chupacabra = "TLSv1.0 minimum enabled in " + data[data.index('config wanopt ssl-server') + 1].split("edit ")[1] + " wanopt SSL profile"
            suggestion = "Upgrade to FOS 5.0.11 or 5.2.3 is advised for FortiGate with CP processors."
            wanopt = True
        if "set ssl-max-version tls-1.0" in data:
            chupacabra = "TLSv1.0 maximum enabled in " + data[data.index('config wanopt ssl-server') + 1].split("edit ")[1] + " wanopt SSL profile"
            suggestion = "Upgrade to FOS 5.0.11 or 5.2.3 is advised for FortiGate with CP processors."
            wanopt = True
        if "set ssl-max-version ssl-3.0" in data:
            chupacabra = "SSLv3 maximum enabled in " + data[data.index('config wanopt ssl-server') + 1].split("edit ")[1] + " wanopt SSL profile"
            suggestion = "config wanopt ssl-server\n" + data[data.index('config wanopt ssl-server') + 1] + "\nedit " + data[data.index('config wanopt ssl-server') + 1].split("edit ")[1] + "\nset ssl-max-version tls-1.2\nend\nend"
            wanopt = True
        p=re.compile(r'set ssl-dh-bits.*(768|1024|1536).*')
        if p.findall(entry):
            chupacabra = "AES DH prime lower than 2048 bits is used"
            suggestion = "config wanopt ssl-server\n" + data[data.index('config wanopt ssl-server') + 1] + "\nedit " + data[data.index('config wanopt ssl-server') + 1].split("edit ")[1] + "\nset ssl-dh-bits 2048\nend\nend"
            wanopt = True
    # I found a chupacabra
    if chupacabra:
        print("\033[93m" + "[*] " + chupacabra + " [*]" + "\033[0m")
        print("\033[40m" + str(data) + "\033[0m")
        print("\033[91m" + vdom_header + suggestion + vdom_footer + "\033[0m" + "\n")
        if sslvpn:
            return 1
        if webgui:
            return 2
        if ssloffload:
            return 3
        if voip:
            return 4
        if wanopt:
            return 5
    else:
        return 0


def main(args):
    """fgtsslaudit.py start main function."""
    if len(args) != 2:
        print("Usage: python ./fgtsslaudit.py fgt.conf")
        return

    # Welcome banner
    banner = chr(176) + " fgtsslaudit.py - FortiOS SSL/TLS configuration audit " + chr(176)
    print(chr(176) * len(banner))
    print(banner)
    print(chr(176) * len(banner) + "\n")

    # Variables declaration
    ctxdata = []         # Tree and leaves
    ctxcnt = 0           # Leading white spaces count
    ctxidx = 0           # Leaf context index
    ctxtab = 4           # Default FortiOS whitespace count per leaf
    ctxvdom = ""         # Current vdom
    statistic = 0        # Feature to fix
    stats_sslvpn = 0     # SSL VPN statistics
    stats_webgui = 0     # Web GUI statistics
    stats_ssloffload = 0 # SSL offload statistics
    stats_voip = 0       # VoIP statistics
    stats_wanopt = 0     # Wan optimization statistics

    # Read FortiOS show full-configuration
    with open(args[1]) as x: lines = x.readlines()
    # List includes tree leaves (configuration parser)
    for line in lines:
        ctxcnt = len(line) - len(line.lstrip())
        ctxidx = int(ctxcnt / ctxtab)
        try:
            ctxdata[ctxidx] = line.strip()
        except:
            ctxdata.insert(ctxidx, line.strip())
        ctxdata[ctxidx + 1:] = []
        # vdom context detection
        if len(ctxdata) == 1:
            if ctxdata[0].startswith("edit "):
                ctxvdom = ctxdata[0].split("edit ")[1].strip()
            if ctxdata[0] == "config global":
                ctxvdom = "config global"
        statistic = audit(ctxdata, ctxvdom) # audit & report
        if statistic == 1:
            stats_sslvpn += 1
        if statistic == 2:
            stats_webgui += 1
        if statistic == 3:
            stats_ssloffload += 1
        if statistic == 4:
            stats_voip += 1
        if statistic == 5:
            stats_wanopt += 1
    print("Configuration objects requiring attention:")
    print("SSL VPN:           " + str(stats_sslvpn))
    print("Web GUI:           " + str(stats_webgui))
    print("SSL offload:       " + str(stats_ssloffload))
    print("VoIP:              " + str(stats_webgui))
    print("Wan optimization:  " + str(stats_webgui))
    print("\nGenerated on " + strftime("%Y-%m-%d %H:%M:%S", gmtime()) + " by fgtsslaudit.py v" + __version__)

if __name__ == '__main__':
    main(sys.argv)
