import abc
import ast
import os
import pprint
import re
import sys
import traceback
from subprocess import CalledProcessError
from subprocess import check_output
from tempfile import NamedTemporaryFile

import simplejson as json
from django.db.models import Q
from lxml import etree

import nmap
import pexpect
from dcim.constants import BMC_POWER_CHOICES
from dcim.constants import BMC_POWER_CYCLE
from dcim.constants import BMC_POWER_OFF
from dcim.constants import BMC_POWER_ON
from dcim.constants import BMC_POWER_ON_UEFI
from dcim.constants import DEVICE_STATUS_ACTIVE
from dcim.constants import DEVICE_STATUS_OFFLINE
from dcim.constants import DEVICE_STATUS_POWERED_OFF
from dcim.constants import IFACE_MODE_TAGGED
from dcim.constants import INTERFACE_TYPE_HOST_OS
from dcim.constants import INTERFACE_TYPE_MANAGEMENT
from dcim.constants import INTERFACE_TYPE_SWITCH_PORT
from dcim.models import Device
from dcim.models import Interface
from dcim.models import InterfaceConnection
from dcim.models import InterfaceMacTraffic
from ipam.models import VLAN
from netaddr import EUI
from utilities.discovery import RemoteDiscovery


class SwitchByCli:
    """Query switch.

    Telnet into cicso switch and run its IOS commands
    https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/s1/sec-s1-xe-3se-5700-cr-book/sec-s1-xe-3se-5700-cr-book_chapter_010.html
    """

    def __init__(self, ip, username=None, pwd=None, mode="enos"):
        self.ip = ip
        self.username = username
        self.pwd = pwd
        self.mode = mode

    def connect(self):
        self.session = pexpect.spawn("telnet %s" % self.ip,
                                     ignore_sighup=False,
                                     timeout=60,
                                     maxread=5000)

        try:
            # swich sometimes ask for username, sometime not!
            i = self.session.expect(["(username|login)", "(p|P)assword"])
            if i == 0:
                print "sending username [%s]" % self.username
                self.session.sendline(self.username)
                self.session.expect("(p|P)assword")
        except:
            print "-" * 100
            traceback.print_exc(file=sys.stdout)
            print "-" * 100
            print "connection timeout on %s" % self.ip
            self.close()
            return None

        print "sending pwd [%s]" % self.pwd
        self.session.sendline(self.pwd)

        noise = ["topology change", "login from host"]
        self.session.expect(noise + [">", "#"])

        if self.mode == "enos":
            self.session.sendline("\n")

            # be quiet
            self.session.sendline("no console")
            self.session.expect(["Disabled", pexpect.EOF])

            # enable superuser mode
            self.session.sendline("en")
            self.session.expect(["granted", pexpect.EOF])
        else:
            # self.session.expect("NOS")
            self.session.sendline("\n")
            self.session.sendline("en")

        self.session.expect(["#", ">"])

        return self.session

    def close(self):
        self.session.close()
        self.session = None

    def get_mac_address(self, switch):
        # read MAC address table from switch
        mac_table = {
            "cnos": self.get_mac_address_cnos,
            "enos": self.get_mac_address_enos
        }[self.mode]()

        # parse MAC table
        if not mac_table:
            print "mac table query has failed. abort."
            return

        for mac, vlan_id, switch_port_name, state, is_openflow in mac_table:

            # mac can be formatted as "00:af" or "000.ed5"
            # we normalize them all into "00:af:a0:98"
            mac = self._cleanse_mac(mac)

            # vlan
            vlan, created = VLAN.objects.get_or_create(vid=vlan_id)

            # create Interface and link to switch
            switch_port_name = self._cleanse_port(switch_port_name)

            # Note: there are two interfaces we are to create:
            # 1. an switch port: device=switch, name = port number
            # 2. an interface on the other end of a switch traffic. Standing
            #    from POV of a switch, we don't know which device it belongs to.

            # create switch port as Interface
            existing = Interface.objects.filter(
                device=switch,
                name=switch_port_name)
            if existing:
                m = existing[0]
                m.type = INTERFACE_TYPE_SWITCH_PORT
            else:
                m = Interface(
                    device=switch,
                    name=switch_port_name,
                    type=INTERFACE_TYPE_SWITCH_PORT)

            m.enabled = True
            m.mode = DEVICE_STATUS_ACTIVE
            m.state = state
            m.save()
            m.tagged_vlans.add(vlan)

            # Create Interface on other side of traffic.
            # Note: we don't know the interface type.
            existing = InterfaceMacTraffic.objects.filter(
                interface=m, mac_address=mac)
            if not existing:
                InterfaceMacTraffic(interface=m, mac_address=mac).save()

    def get_hostname(self, switch):
        # dump switch host name
        name = {
            "cnos": self.get_hostname_cnos,
            "enos": self.get_hostname_enos
        }[self.mode]()

        # update switch if we get a name from switch itself
        if name:
            switch.name = name
            switch.save()

    def get_neighbors(self, switch):
        # dump LLDP neighbors
        resp = {
            "cnos": self.get_neighbors_cnos,
            "enos": self.get_neighbors_enos
        }[self.mode]()

        # parse response
        # example: [(my_port, remote_interface, remote_port),]
        for my_port, remote_port, remote_interface in resp:
            existing = Interface.objects.filter(
                device=switch,
                name=my_port,
            )
            if existing:
                me = existing[0]
            else:
                me = Interface(device=switch, name=my_port)
            me.type = INTERFACE_TYPE_SWITCH_PORT
            me.save()

            # (me, them) pair. Do they exist?
            if InterfaceConnection.objects.filter(
                    Q(interface_a=remote_interface, interface_b=me) |
                    Q(interface_a=me, interface_b=remote_interface)):
                # nothing to do
                return
            else:
                InterfaceConnection(interface_a=me, interface_b=remote_interface).save()

    def get_system_info(self, switch):
        # dump switch system info
        mac, serial, part_no, mtm = {
            "cnos": self.get_system_info_cnos,
            "enos": self.get_system_info_enos
        }[self.mode]()

        # update switch:
        # 1. serial
        # 2. switch device's device type part number
        switch.serial = serial
        switch.save()

        switch.device_type.part_number = part_no
        switch.device_type.save()

        # From mac we create/update Interface
        existings = Interface.objects.filter(mac_address=mac)
        if existings:
            if existings.filter(device=switch):
                pass
            else:
                existings.update(device=switch)
            interface = existings[0]
        else:
            existing_mgmt = Interface.objects.filter(device=switch,
                                                     name="mgmt0")
            if existing_mgmt:
                interface = existing_mgmt[0]
            else:
                interface = Interface(
                    name="mgmt0",  # used on CNOS switch at least.
                    device=switch
                )
        interface.device = switch
        interface.mac_address = mac
        interface.type = INTERFACE_TYPE_MANAGEMENT
        interface.save()

        # link interface to secret & ip
        switch.primary_ip.interface = interface
        switch.primary_ip.save()

        ip, secret = switch.management_access
        secret.interface = interface

    def dump_port_mac(self, switch):
        port_table = {
            "cnos": self.dump_port_mac_cnos,
            "enos": self.dump_port_mac_enos
        }[self.mode]()

        for port_number, mac, enabled in port_table:
            existing = Interface.objects.filter(
                device=switch,
                name=port_number
            )
            if existing:
                i = existing[0]
            else:
                i = Interface(
                    device=switch,
                    name=port_number,
                )
            i.mac_address = mac
            i.type = INTERFACE_TYPE_SWITCH_PORT
            i.enabled = enabled
            i.save()

    def get_port_info(self, switch):
        port_info = {
            "cnos": self.get_port_info_cnos,
            "enos": self.get_port_info_enos
        }[self.mode]()

        for (port_id, is_trunk, native_vlan, allowed_vlans) in port_info:
            existing = Interface.objects.filter(
                device=switch,
                name=port_id,
            )
            if existing:
                me = existing[0]
            else:
                me = Interface(device=switch, name=port_id)
            me.type = INTERFACE_TYPE_SWITCH_PORT
            me.is_trunk = is_trunk
            me.mode = IFACE_MODE_TAGGED

            # native vlan
            try:
                int(native_vlan)
            except:
                print "error:", port_id, native_vlan, allowed_vlans

            vlan, created = VLAN.objects.get_or_create(
                vid=int(native_vlan))
            me.untagged_vlan = vlan

            # allowed vlan list
            me.allowed_vlans = ",".join(allowed_vlans)
            me.save()

    def _cleanse_port(self, port):
        """Helper to clean port name.

        Port name can be in straight \d+ or with something like
        `Ethernet/54` format, in which case we will strip to acquire
        `54`.
        """
        if "/" in port:
            return port.split("/")[-1].strip()
        elif "-" in port:
            # we see port in format of a MACA
            # eg. 68-05-ca-62-ef-a5
            return port.replace("-", ":")
        return port.strip()

    def _cleanse_mac(self, mac):
        """Unify MAC address format.

        MAC address can be found in many forms:
        1. 68-05-ca-62-f3-fc
        2. 68 05 ca 62 f3 fc
        3. 68:05:ca:62:f3:fc
        4. A48C.DB34.B200

        We will normalize them to be capital letters using
        ':' for delimiter.

        Args:
          mac (str): a MAC address

        Return:
          str: Capitalizaed MAC address with `:` as delimiter.
        """
        tmp = re.sub("[-\s:.]", "", str(mac))
        return EUI(tmp)

    def _dump_info(self, cmd, expect):
        noise = ["topology change", "login from host"]

        if not self.session:
            return

        print "sending `%s`" % cmd
        self.session.sendline(cmd)
        i = self.session.expect(noise + [expect])
        while i < 2:  # we are matching noises
            self.session.sendline("en")
            i = self.session.expect(noise + [expect])

        # read buffer
        tmp = ''
        while self.session.after.strip() == expect:
            tmp += self.session.before
            self.session.sendline(" ")  # whitespace
            self.session.expect([expect, ".*[#>]", pexpect.EOF])

        tmp += self.session.after

        tmp = re.sub(r'[^\x00-\x7f]', r'', tmp, re.MULTILINE)
        tmp = re.sub(u"\u0008", " ", tmp)
        tmp = tmp.replace("\x1b[0m", "\n")
        tmp = tmp.replace("\x1b[7m----\x1b[m\x07\x00", "")
        tmp = tmp.replace("\x1b[7m", "")
        tmp = tmp.replace("\x1b[m", "")
        tmp = tmp.replace("\x00", "")
        return tmp

    ##########################
    # ENOS command
    #########################

    def get_system_info_enos(self):
        """ENOS firmware using `show sys-info` cli.
        """
        tmp = self._dump_info("show sys-info", "any other key")

        # Example output:
        #
        # ```
        # MAC address: 74:99:75:c3:6c:00    IP (If 1) address: 10.240.43.28
        # Hardware Revision: 0
        # Board Revision: 2
        # Switch Serial No: Y010CM33G018
        # Hardware Part No: BAC-00069-00        Spare Part No: BAC-00069-00
        # Manufacturing date: 13/10

        # MTM Value: 7159-52F
        # ESN: MM11001
        # ```
        mac = re.search("^MAC address:\s+(?P<mac>\S+)",
                        tmp, re.MULTILINE).group("mac")
        mac = self._cleanse_mac(mac)

        serial = re.search("^Switch Serial No:\s+(?P<serial>\S+)",
                           tmp, re.MULTILINE).group("serial")
        part_no = re.search("^Hardware Part No:\s+(?P<part_no>\S+)",
                            tmp, re.MULTILINE).group("part_no")
        mtm = re.search("^MTM Value:\s+(?P<mtm>\S+)",
                        tmp, re.MULTILINE).group("mtm")

        return (mac, serial, part_no, mtm)

    def get_mac_address_enos(self):
        """ENOS firmware using `show mac` cli.
        """
        tmp = self._dump_info("show mac", "any other key")

        # strip off garbage till the mac table header.
        #
        # Sample:
        # MAC address       VLAN     Port    Trnk  State  Permanent  Openflow
        # -----------------  --------  -------  ----  -----  ---------  --------
        header = re.search("Openflow\s+(.*)", tmp).group(1)
        print "found mac table in %s" % self.ip

        # header is removed
        mac = re.split("%s" % header, tmp)[-1]

        # parse mac table
        mac = filter(lambda x: x, mac.split("\n"))

        # parse mac line
        mac = filter(lambda x: re.search("(\w{2}[:]){5}.*", x), mac)
        mac = map(lambda x: re.search("(\w{2}[:]){5}.*", x).group(0).strip(), mac)

        # cleanse data
        mac_table = []
        for m in list(mac):
            try:
                tmp = re.split("\s+", m)
                mac_address = self._cleanse_mac(tmp[0])
                vlan_id = int(tmp[1].strip())
                switch_port_name = tmp[2].strip()
                state = tmp[3].strip()
                is_openflow = True if tmp[4] == "Y" else False
                mac_table.append((mac_address,
                                  vlan_id,
                                  switch_port_name,
                                  state,
                                  is_openflow))
            except:
                print '*' * 80
                print m
        return mac_table

    def get_hostname_enos(self):
        """Get switch name.
        """
        tmp = self._dump_info("show run", "More")

        # Example:
        # hostname "LCTC-R2U37-SW"
        tmp = filter(lambda x: "hostname" in x, tmp.split("\n"))

        # Nothing found!!
        if not tmp:
            return None

        tmp = re.search("(?<=hostname\s)(?P<hostname>.*)", tmp[0].strip()).group("hostname")
        return tmp.replace("\"", "").strip()

    def get_neighbors_enos(self):
        """Dump `lldp remote-device` table.

        Example output:

        ```
        LLDP Remote Devices Information
        Legend(possible values in DMAC column) :
        NB   - Nearest Bridge          - 01-80-C2-00-00-0E
        NnTB - Nearest non-TPMR Bridge - 01-80-C2-00-00-03
        NCB  - Nearest Customer Bridge - 01-80-C2-00-00-00
        Total number of current entries: 2
        LocalPort | Index | Remote Chassis ID         | Remote Port          | Remote System Name            | DMAC
        ----------|-------|---------------------------|----------------------|-------------------------------|---------
        2         | 2     | a4 8c db 34 d9 00         | MGT                  |                               | NB
        XGE4      | 1     | a4 8c db 34 d7 00         | 48                   |
        LCTC-R2U37-SW                 | NB
        ```

        Returns:
          tuple: (myport, remote_port, remote_interface)
        """
        tmp = self._dump_info("show lldp remote-device", "LocalPort")
        records = []  # [(myport, remote_interface, remote_port),]
        entries = filter(lambda x: "|" in x, tmp.split("\n"))[2:]
        for e in entries:
            tmp = map(lambda x: x.strip(), e.split("|"))

            remote_port = self._cleanse_port(tmp[3])
            if not remote_port:
                continue

            my_port = self._cleanse_port(tmp[0])
            if not my_port:
                continue

            # remote device
            remote_switch_name = tmp[4].lstrip("\x00").strip()
            existing_devices = Device.objects.filter(name=remote_switch_name)
            if not existing_devices:
                # we haven't seen this device yet,
                # wait for next scan
                continue
            remote_device = existing_devices[0]

            # remote interface
            existing_interfaces = Interface.objects.filter(
                name=remote_port,
                device=remote_device)
            if existing_interfaces:
                remote_interface = existing_interfaces[0]
            else:
                remote_interface = Interface(name=remote_port,
                                             device=remote_device)
            remote_interface.mac_address = self._cleanse_mac(tmp[2])
            remote_interface.save()

            records.append((my_port, remote_port, remote_interface))

        return records

    def dump_port_mac_enos(self):
        """Dump port MAC mapping.

        Example output:

        RS G8272#show lldp port
        LLDP Port Info
        -  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        Port    MAC address       MTU  PortEnabled AdminStatus RxChange TrapNotify
        ======= ================= ==== =========== =========== ======== ==========
        1       a4:8c:db:9b:01:00 9216 enabled     tx_rx       no       disabled
        2       a4:8c:db:9b:01:00 9216 enabled     tx_rx       no       disabled

        Return:
          list: of tuple (port number, MAC)
        """
        tmp = self._dump_info("show lldp port", "any other key")
        tmp = filter(lambda x: x.strip(), re.split("=+", tmp)[-1].split("\n"))

        port_table = []
        for a in tmp:
            p = re.split("\s+", a.strip())
            if "port" in p[0].lower():
                break
            elif re.search("press", p[0].lower()):
                continue

            mac = filter(lambda x: ":" in x, p)
            if not mac:
                continue
            port_table.append((self._cleanse_port(p[0]),
                               self._cleanse_mac(mac[0]),
                               True if p[3].lower() == "enabled" else False))

        return port_table

    def get_port_info_enos(self):
        """ Using `show interface information` to get:

        1. native vlan
        2. is trunk?
        3. allowed VLANs on each port

        Returns:
          list: list of tuple (port ID, is_trunk, native vlan ID, [allow vlans])
        """

        tmp = self._dump_info("show interface information", "any other key")

        # Alias    Port Tag RMON Lrn Fld Openflow tis tes PVID     DESCRIPTION  VLAN(s)
        #               Trk                               NVLAN
        # -------- ---- --- ---- --- --- -------- --- --- ------ -------------- --
        # 1        1     n   d    e   e      d     d   d     1                  1
        # 2        2     n   d    e   e      d     d   d     1                  1
        # 3        3     n   d    e   e      d     d   d     1                  1
        # 17       17    y   d    e   e      d     d   d     1                  1-19 100-10

        header_split = re.findall("-{2,}", tmp)
        table = re.split(" ".join(header_split), tmp)[-1]

        # pull the col headers. This is really messy because
        # 3 switches give me 3 different sets of header values!
        # So we have to lookup the index of the col we want to parse.
        # sad.
        header = re.search("^(?P<header>(Alias|Port)[\w\s]+RMON.*)$", tmp, re.M).group("header")
        header = re.split("\s+", header.strip())

        port = None
        is_trunk = None
        native_vlan = None
        allowed_vlans = None
        result = []

        for line in table.split("\n"):
            # must have! line has some invisible characters at
            # the beginning, sometimes!
            line = line.strip()

            # remove noise
            if re.search("any\sother|continue|[#=]", line) or not line.strip():
                continue

            noise = False
            for x in ["tagged", "Trunk mode", "Native-VLAN"]:
                if x in line:
                    noise = True
                    break
            if noise:
                continue

            if re.search("[deny].*\d$", line):
                # get `port`
                idx = header.index("Port")
                start = sum([len(header_split[x]) + 1 for x in range(idx)]) - 1
                end = sum([len(header_split[x]) + 1 for x in range(idx + 1)]) - 1
                p = line[max(start, 0):end].strip()

                # print line
                # print "idx: %d" % idx, "start: %d" % start, "end: %d" % end, "port: %s"
                # % port, "p: %s" % p

                if p and (not port or port != p):
                    # this a line w/ a load of info
                    if port and port != p:
                        # we are seeing info of a new port, save
                        result.append((port, is_trunk,
                                       native_vlan,
                                       filter(lambda x: x, allowed_vlans)))

                        # get `alias`
                        if "Alias" in header:
                            idx = header.index("Alias")
                            start = sum([len(header_split[x]) + 1 for x in range(idx)]) - 1
                            end = sum([len(header_split[x]) + 1 for x in range(idx + 1)]) - 1
                            alias = line[max(start, 0):end].strip()
                        else:
                            # this layout has no alias colum.
                            alias = port

                        # reset these values
                        port = p
                    if not port:
                        port = p

                    # get `is trunk`
                    idx = header.index("Tag")
                    start = sum([len(header_split[x]) + 1 for x in range(idx)]) - 1
                    end = sum([len(header_split[x]) + 1 for x in range(idx + 1)]) - 1
                    trunk = line[max(start, 0):end].strip()
                    if trunk == "n":
                        is_trunk = False
                    elif trunk == "y":
                        is_trunk = True

                    # get native vlan
                    try:
                        idx = header.index("PVID")
                        start = sum([len(header_split[x]) + 1 for x in range(idx)]) - 1
                        end = sum([len(header_split[x]) + 1 for x in range(idx + 1)]) - 1
                        native_vlan = line[max(start, 0):end].strip()
                    except:
                        print "ip: %s" % self.ip
                        print "header:", header
                        print line
                        print "idx: %d" % idx, "start: %d" % start, "end: %d" % end, "port: %s" % port, "p: %s" % p

                # get allowed vlans
                idx = header.index("VLAN(s)")
                start = sum([len(header_split[x]) + 1 for x in range(idx)]) - 1
                end = sum([len(header_split[x]) + 1 for x in range(idx + 1)]) - 1
                allowed_vlans = re.split("\s+", line[max(start, 0):].strip())
            else:
                if re.search("\d+[\d\s-]+", line):
                    allowed_vlans += re.split("\s+", line)

        result.append((port, is_trunk, native_vlan, allowed_vlans))
        return result

    ##########################
    # CNOS command
    #########################

    def get_mac_address_cnos(self):
        """CNOS firmware using `display mac address-table` cli.
        """
        tmp = self._dump_info("display mac address-table", "More")

        # strip off garbage till the mac table header.
        #
        # Sample:
        # > VLAN     MAC Address     Type      Ports
        # > -----+----------------+---------+-----------------------+
        header = re.search("MAC Address\s+(.*)", tmp).group(1)
        print "found mac table in %s" % self.ip

        # header is removed
        mac = re.split("%s" % header, tmp)[-1]

        # parse mac table
        mac = filter(lambda x: re.search("^\d+", x.strip()), mac.split("\n"))

        # cleanse data
        mac_table = []

        for m in mac:
            tmp = re.split("\s+", m.strip())[-4:]

            # NOTE: for some reason, tmp can has a mis-formatted data!
            # Example:
            # ['\x1b[7m--\x1b[m\x07\x00', '100', '88f0.31db.fd11', 'dynamic', 'Ethernet1/54']
            # So we always take the last 4 elements as if they are valid!
            vlan_id = int(tmp[0].strip())
            mac_address = self._cleanse_mac(tmp[1])
            switch_port_name = self._cleanse_port(tmp[3])
            state = None
            is_openflow = False
            mac_table.append((mac_address, vlan_id, switch_port_name, state, is_openflow))

        return mac_table

    def get_hostname_cnos(self):
        tmp = self._dump_info("display run", "More")

        # Example:
        # hostname "LCTC-R2U37-SW"

        tmp = filter(lambda x: "hostname" in x, tmp.split("\n"))

        # Nothing found!!
        if not tmp:
            return None

        tmp = re.search("(?<=hostname\s)(?P<hostname>.*)", tmp[0].strip()).group("hostname")
        return tmp

    def get_neighbors_cnos(self):
        """Dump LLDP neighbors.

        Returns:
          tuple: (myport, remote_port, remote_interface)
        """
        tmp = self._dump_info("display lldp neighbors", "Port")

        # Sample output:
        #
        # > LCTC-R1U37-SW#display lldp neighbors
        # > Capability codes:
        # >   (R) Router, (B) Bridge, (T) Telephone, (C) DOCSIS Cable Device
        # >   (W) WLAN Access Point, (P) Repeater, (S) Station, (O) Other
        # > Device ID            Local Intf      Hold-time  Capability   ID
        # >                      Ethernet1/5     120
        # >                      Ethernet1/7     120
        # >                      Ethernet1/22    120
        # > # LCTC-R1U39-SW        Ethernet1/48    120        BR          XGE4
        # > # LCTC-R3U38-SW        Ethernet1/54    120        BR          1
        # > # LCTC-R1U39-SW        mgmt0           120        BR          47
        # >
        # > # Total entries displayed: 6
        # > # LCTC-R1U37-SW#
        # >

        # strip off a whole bunch of garbages
        tmp = re.search("Device\s+ID(?P<lldp>.*)(?=Total\s+entries)",
                        tmp, re.S | re.M).group("lldp")

        # first line is a header, remove.
        tmp = map(lambda x: x.strip(), tmp.split("\n")[1:])

        # ASSUMPTION: valid entry has 5 columns!
        tmp = filter(lambda x: len(x) == 5, [re.split("\s+", x) for x in tmp])
        records = []  # [(my_port, remote_switch_name, remote_port),]
        for line in tmp:
            # my port
            my_port = self._cleanse_port(line[1])
            if not my_port:
                continue

            # remote port
            remote_port = self._cleanse_port(line[-1])
            if not remote_port:
                continue

            # remote device
            remote_switch_name = line[0].lstrip("\x00").strip()
            existing_devices = Device.objects.filter(name=remote_switch_name)
            if not existing_devices:
                # we haven't seen this device yet,
                # wait for next scan
                continue
            remote_device = existing_devices[0]

            # remote interface
            remote_interface, created = Interface.objects.get_or_create(
                device=remote_device,
                name=remote_port
            )

            # normalized data
            records.append((my_port, remote_port, remote_interface))
        return records

    def get_system_info_cnos(self):
        tmp = self._dump_info("display sys-info", "System Name")

        # Example output:
        #
        # ```
        # *** display boot ***
        # Current ZTP State: Enable
        # Current FLASH software:
        #   active image: version 10.3.2.0, downloaded 13:57:07 Wed Jan 18, 2000
        #   standby image: version unknown, downloaded unknown
        #   Uboot: version 10.3.2.0, downloaded 13:57:07 Wed Jan 18, 2000
        #   ONIE: empty
        # Currently set to boot software standby image
        # Current port mode: default mode

        # *** display env fan detail ***
        # Total Fan: 8
        # +--------+-----+-----------------+---------------+-------+--------+
        # | Module | Fan | Name            | Air-Flow      | Speed | Speed  |
        # | Number | ID  |                 | Direction     | (%)   | (RPM)  |
        # +--------+-----+-----------------+---------------+-------+--------+
        #   01       01    Fan 1             Front-to-Back   19      3904
        #   01       02    Fan 2             Front-to-Back   20      4235
        #   02       03    Fan 3             Front-to-Back   20      3924
        #   02       04    Fan 4             Front-to-Back   21      4225
        #   03       05    Fan 5             Front-to-Back   19      3870
        #   03       06    Fan 6             Front-to-Back   20      4176
        #   04       07    Fan 7             Front-to-Back   20      3882
        #   04       08    Fan 8             Front-to-Back   21      4109

        # *** display env power ***
        # Total Power Supplies: 2
        # +----+-----------------+----------------+-----------------+---------------+
        # | ID | Name            | Manufacturer   | Model           | State         |
        # +----+-----------------+----------------+-----------------+---------------+
        #   01   Power Supply 1    DELTA            XXXXXXXXXX        Normal ON
        #   02   Power Supply 2    DELTA            XXXXXXXXXX        Normal ON

        # *** display env temperature ***
        # +----+------------------+----------+--------+
        # | ID | Name             | Temp     | State  |
        # |    |                  | (Celsius)|        |
        # +----+------------------+----------+--------+
        #   01   CPU Local          28         OK
        #   02   Ambient            26         OK
        #   03   Hot Spot           44         OK

        # System Name:                     G8272
        # System Description:              G8272 ("48x10GE + 6x40GE")
        # System Model:                    LENOVO G8272
        # System Manufacture Date:         1719
        # System Serial Number:            Y05NJ111GLC3
        # System PCB Assembly:             00CJ067
        # System PCB Assembly Revision:
        # System Board Revision:
        # System Electronic Serial Number: J11GLC3
        # System Firmware Revision:        10.3.2.0
        # System Software Revision:        10.3.2.0
        # LCTC-R1U37-SW#display sys-info

        # *** display boot ***
        # Current ZTP State: Enable
        # Current FLASH software:
        #   active image: version 10.3.2.0, downloaded 13:57:07 Wed Jan 18, 2000
        #   standby image: version unknown, downloaded unknown
        #   Uboot: version 10.3.2.0, downloaded 13:57:07 Wed Jan 18, 2000
        #   ONIE: empty
        # Currently set to boot software standby image
        # Current port mode: default mode

        # *** display env fan detail ***
        # Total Fan: 8
        # +--------+-----+-----------------+---------------+-------+--------+
        # | Module | Fan | Name            | Air-Flow      | Speed | Speed  |
        # | Number | ID  |                 | Direction     | (%)   | (RPM)  |
        # +--------+-----+-----------------+---------------+-------+--------+
        #   01       01    Fan 1             Front-to-Back   19      3938
        #   01       02    Fan 2             Front-to-Back   20      4238
        #   02       03    Fan 3             Front-to-Back   20      3915
        #   02       04    Fan 4             Front-to-Back   21      4222
        #   03       05    Fan 5             Front-to-Back   19      3865
        #   03       06    Fan 6             Front-to-Back   20      4173
        #   04       07    Fan 7             Front-to-Back   20      3868
        #   04       08    Fan 8             Front-to-Back   21      4109

        # *** display env power ***
        # Total Power Supplies: 2
        # +----+-----------------+----------------+-----------------+---------------+
        # | ID | Name            | Manufacturer   | Model           | State         |
        # +----+-----------------+----------------+-----------------+---------------+
        #   01   Power Supply 1    DELTA            XXXXXXXXXX        Normal ON
        #   02   Power Supply 2    DELTA            XXXXXXXXXX        Normal ON

        # *** display env temperature ***
        # +----+------------------+----------+--------+
        # | ID | Name             | Temp     | State  |
        # |    |                  | (Celsius)|        |
        # +----+------------------+----------+--------+
        #   01   CPU Local          28         OK
        #   02   Ambient            26         OK
        #   03   Hot Spot           44         OK

        # System Name:                     G8272
        # System Description:              G8272 ("48x10GE + 6x40GE")
        # System Model:                    LENOVO G8272
        # System Manufacture Date:         1719
        # System Serial Number:            Y05NJ111GLC3
        # System PCB Assembly:             00CJ067
        # System PCB Assembly Revision:
        # System Board Revision:
        # System Electronic Serial Number: J11GLC3
        # System Firmware Revision:        10.3.2.0
        # System Software Revision:        10.3.2.0
        #
        serial = re.search("Serial Number:\s+(?P<serial>\S+)",
                           tmp, re.MULTILINE).group("serial")
        part_no = re.search("PCB Assembly:\s+(?P<part_no>\S+)",
                            tmp, re.MULTILINE).group("part_no")
        mac = self.get_management_mac_cnos()
        return (mac, serial, part_no, None)

    def get_management_mac_cnos(self):
        tmp = self._dump_info("display interface mgmt 0", "mgmt")

        # Example output:
        #
        # ```
        # Interface mgmt0
        #   Hardware is Management Ethernet  Current HW addr: a48c.db34.b200
        #   Physical:a48c.db34.b200  Logical:(not set)
        #   index 3 metric 1 MTU 1500 Bandwidth 1000000 Kbit
        #   no bridge-port
        #   arp ageing timeout 1500
        #   <UP,BROADCAST,RUNNING,ALLMULTI,MULTICAST>
        #   VRF Binding: Associated with management
        #   Speed 1000 Mb/s Duplex full
        #   IPV6 DHCP IA-NA client is enabled.
        #   inet 10.240.41.147/22 broadcast 10.240.43.255
        #   inet6 fe80::a68c:dbff:fe34:b200/64
        #   RX
        #     0 input packets 18446744073706919455 unicast packets 1195336 multicast packets
        #     2278852 broadcast packets 2406868214 bytes
        #   TX
        #     42183 output packets 20173 unicast packets 21988 multicast packets
        #     22 broadcast packets 4842042 bytes
        # Automatic policy provisioning is disabled on this interface
        # ```
        mac = re.search("Physical:(?P<mac>\S+)", tmp).group("mac")
        return self._cleanse_mac(mac)

    def dump_port_mac_cnos(self):
        """Dump (port, MAC) pairs.

        Example output:
        ```
        Interface Information
         Enable (tx/rx/trap): Y/Y/N   Port Mac address: a4:8c:db:34:b2:03

        Interface Name: Ethernet1/2
        --------------
        Interface Information
         Enable (tx/rx/trap): Y/Y/N   Port Mac address: a4:8c:db:34:b2:04

        Interface Name: Ethernet1/3
        --------------
        Interface Information
         Enable (tx/rx/trap): Y/Y/N   Port Mac address: a4:8c:db:34:b2:05

        Interface Name: Ethernet1/4
        --------------
        Interface Information
         Enable (tx/rx/trap): Y/Y/N   Port Mac address: a4:8c:db:34:b2:06
        ```

        Returns:
          list: of tuple (port number, MAC)
        """
        port_table = []
        tmp = self._dump_info("display lldp interface all", "More")
        for a in filter(lambda x: x, re.split("\s(?=Interface Name)", tmp)):
            if "mac address" not in a.lower():
                continue

            port = re.search("Interface Name:\s(?P<port>\S+)", a, re.MULTILINE).group("port")
            port = self._cleanse_port(port)
            mac = re.search("Mac\saddress:\s(?P<mac>\S+)", a, re.MULTILINE).group("mac")
            mac = self._cleanse_mac(mac)

            # ASSUMPTION: port is always ENABLED!
            port_table.append((port, mac, True))

        return port_table

    def get_port_info_cnos(self):
        """Get port info:

        1. is trunk
        2. native vlan ID
        3. allowed vlans
        """
        tmp = self._dump_info("display interface trunk", "More")

        # there are 3 sections in this dump, we have to separate them
        # first.
        tmp = tmp.split("Vlans Allowed")
        trunk_native_vlan_table = tmp[0]
        vlan_allowed_table = tmp[1].split("Port")[0]

        result = {}
        # print trunk_native_vlan_table
        # for line in filter(lambda x: re.search("(ethernet|po)\d+", x.lower()),
        #                    trunk_native_vlan_table.split("\n")):

        for line in re.findall("(?=Ethernet\d|po\d).*$",
                               trunk_native_vlan_table, re.MULTILINE):
            p = re.split("\s+", line.strip())

            # ---------------------------------------------------------------
            # Port           Native        Status    Port
            #                Vlan                    Agg
            # ---------------------------------------------------------------
            # Ethernet1/1    3999          trunk       --
            port = self._cleanse_port(p[0])
            result[port] = {
                "native_vlan": p[1],
                "is_trunk": True,
                "allowed_vlans": None
            }

        for line in re.findall("(?=Ethernet\d|po\d).*$",
                               vlan_allowed_table, re.MULTILINE):

            p = re.split("\s+", line.strip())

            # ---------------------------------------------------------------
            # Port           Vlans Allowed on Trunk
            # ---------------------------------------------------------------
            # Ethernet1/1    1-19,100-109,200-209,300-309,400-409,500-509,600-609

            port = self._cleanse_port(p[0])
            if p[-1] == "none":
                allowed_vlans = []
            else:
                allowed_vlans = p[-1].split(",")
            result[port]["allowed_vlans"] = allowed_vlans

        tmp = []
        for port, vals in result.iteritems():
            tmp.append((port,
                        vals["is_trunk"],
                        vals["native_vlan"],
                        vals["allowed_vlans"]))
        return tmp


class HostByCli(RemoteDiscovery):
    """Generic handler of executing a host CLI.

    Parsing in this context is really not predictable as we don't
    know what CLI it executes. Therefore treat this as a catch-all place.
    Once a group of CLI display a resp pattern, we will move them
    out to their own class, eg. HostByEsxShell
    """

    def __init__(self, ip, user, pwd):
        RemoteDiscovery.__init__(self, ip, user, pwd)

    def run_cmd(self, subcmd, module, remote_cmd):
        return self.by_ansible(subcmd, module, remote_cmd)

    def run_cmd_special(self, subcmd, module, remote_cmd):
        return self.by_ansible(subcmd, module, remote_cmd, True)

    def get_mac(self):
        """Poll all interfaces.

        cmd: `ip a`

        Returns:
          list: of tuple (name, mac, ip)
        """
        resp = self.run_cmd("all", "shell", "-a ip a")

        if not resp:  # if None, we don't have access to this IP
            return None

        name_pat = re.compile("^(?P<name>[^:]+)")
        mac_pat = re.compile("(ether|loopback)\s(?P<mac>.*)(?=brd)")
        ip_pat = re.compile("inet\s(?P<ip>\S+)")
        results = []
        for line in re.split("\d+:\s(?=\w|;)", resp):
            mac = mac_pat.search(line)
            if not mac:
                continue

            mac = mac.group("mac").strip()
            mac = mac.replace("-", ":").upper()

            name = name_pat.search(line).group("name")
            if ip_pat.search(line):
                ip = ip_pat.search(line).group("ip")
            else:
                ip = None
            results.append((name, mac, ip))

        return results

    def get_hostname(self):
        """Poll hostname.

        cmd: `hostname`
        """
        resp = self.run_cmd("all", "shell", "-a hostname")
        return resp


class BmcByCli():
    """Generic handler of BMC cli.

    Even though it offers a SSH, it is different from `ansible ssh`.
    So we fall back to using `pexpect` to simulate key ins.
    """

    def __init__(self, ip, username=None, pwd=None, mode="enos"):
        self.ip = ip
        self.username = username
        self.pwd = pwd
        self.mode = mode

    def connect(self):
        self.session = pexpect.spawn(
            "ssh -oStrictHostKeyChecking=no %s@%s" % (self.username, self.ip),
            ignore_sighup=False,
            timeout=60)

        try:
            self.session.expect("Password")
        except:
            print "connection timeout on %s" % self.ip
            self.session.close()
            return None

        print "sending password %s" % self.pwd
        self.session.sendline(self.pwd)
        self.session.expect(">")
        return self.session

    def run_cmd(self, cmd):
        if not self.session:
            return

        print "sending `%s`" % cmd
        self.session.sendline(cmd)
        self.session.expect([">"])
        return self.session.before

    def get_name(self):
        """Get machine name.

        cmd: `info`
        """
        return self.run_cmd("info")

    def get_eth0_mac(self):
        """Get eth0 mac.

        cmd: `ifconfig eth0 -b`
        """
        return self.run_cmd("ifconfig eth0 -b")

    def get_vpd_sys(self):
        return self.run_cmd("vpd sys")

    def get_power_state(self):
        return self.run_cmd("power state")

    def set_power_state(self, state):
        if state not in dict(BMC_POWER_CHOICES):
            raise ValueError

        states = {
            BMC_POWER_ON: "on",
            BMC_POWER_OFF: "off",
            BMC_POWER_CYCLE: "cycle",
            BMC_POWER_ON_UEFI: "uefi"
        }
        return self.run_cmd("power %s" % states[state])

    def get_firmware_status(self):
        """Get firmware status.

        cmd: `vpd fw`
        """
        return self.run_cmd('vpd fw')

    def get_storage_controllers(self):
        """Get RAID controllers.

        cmd: `storage -list controllers`, `storage -show <target>`
        """
        result = []
        name_pat = re.compile("^Product\sName:\s+(?P<name>.*)$", re.M)
        manufacturer_pat = re.compile("^Manufacture:\s+(?P<name>.*)$", re.M)
        part_pat = re.compile("^Part No[.]:\s+(?P<name>.*)$", re.M)
        serial_pat = re.compile("^Serial No[.]:\s+(?P<name>.*)$", re.M)
        uuid_pat = re.compile("^UUID:\s+(?P<name>.*)$", re.M)
        model_pat = re.compile("^Model:\s+(?P<name>.*)$", re.M)

        controllers = self.run_cmd("storage -list controllers")
        for c in re.findall("^(ctrl\S+)", controllers, re.MULTILINE):
            tmp = self.run_cmd("storage -show %s" % c)

            # dump has too many "\r", which makes RE not working!
            tmp = re.sub("\r", "\n", tmp)

            result.append({
                "target": c,
                "name": name_pat.search(tmp).group("name"),
                "manufacturer": manufacturer_pat.search(tmp).group("name"),
                "part_id": part_pat.search(tmp).group("name"),
                "serial": serial_pat.search(tmp).group("name"),
                "asset_tag": uuid_pat.search(tmp).group("name"),
                "model": model_pat.search(tmp).group("name"),
                "description": tmp
            })
        return result

    def get_storage_drives(self):
        """Get disks.

        cmd: `storage -list drives`, `storage -show <target>`
        """
        result = []

        name_pat = re.compile("^Product\sName:\s+(?P<name>.*)$", re.M)
        manufacturer_pat = re.compile("^Manufacture:\s+(?P<name>.*)$", re.M)
        part_pat = re.compile("^Part No[.]:\s+(?P<name>.*)$", re.M)
        serial_pat = re.compile("^Serial No[.]:\s+(?P<name>.*)$", re.M)
        disk_type_pat = re.compile("^Disk Type:\s+(?P<name>.*)$", re.M)
        media_type_pat = re.compile("^Media Type:\s+(?P<name>.*)$", re.M)

        disks = self.run_cmd("storage -list drives")
        for c in re.findall("^(disk\S+)", disks, re.MULTILINE):
            tmp = self.run_cmd("storage -show %s" % c)

            # dump has too many "\r", which makes RE not working!
            tmp = re.sub("\r", "\n", tmp)

            # depending on firmware, some keys may not applicable
            try:
                disk_type = disk_type_pat.search(tmp).group("name")
            except:
                disk_type = None

            result.append({
                "target": c,
                "name": name_pat.search(tmp).group("name"),
                "manufacturer": manufacturer_pat.search(tmp).group("name"),
                "part_id": part_pat.search(tmp).group("name"),
                "serial": serial_pat.search(tmp).group("name"),
                "disk_type": disk_type,
                "media_type": media_type_pat.search(tmp).group("name"),
                "description": tmp
            })
        return result
