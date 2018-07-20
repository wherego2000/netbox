import abc
import ast
import os
import pprint
import re
from subprocess import CalledProcessError
from subprocess import check_output
from tempfile import NamedTemporaryFile

import simplejson as json
from lxml import etree

import nmap
import pexpect


class LocalDiscovery:

    def list_esxi_host(self, net):
        """Discover ESXI hosts on a given network.

        This is based on info
        (https://kb.vmware.com/s/article/1012382) that VMware
        authentication is bound to port 902 on a ESXI host.
        Therefore, `nmap` is to scan for all responses on port 902,
        and we filter responses for a given service name that
        indicates a VMware host.

        Args:
          net (str): a network segment, example `10.243.1.0/24`

        Returns:
          hosts (list): list of dict that has been identified as ESXI host
        """
        nm = nmap.PortScanner()
        nm.scan(hosts=net, arguments="-sV -p 902")
        esxi_hosts = filter(
            lambda x:
            nm[x]["tcp"][902]["product"].lower() == "vmware authentication daemon" and
            nm[x]["tcp"][902]["state"].lower() == "open" and
            nm[x]["tcp"][902]["name"].lower() == "vmware-auth",
            nm.all_hosts()
        )
        return [nm[x] for x in esxi_hosts]


class RemoteDiscovery:
    __metaclass__ = abc.ABCMeta

    """Class to faciliate discovery methods that
    are dependiing on an execution of command/script
    inside the remote target. An obvious mechanism is through Ansible playbooks.
    """

    def __init__(self, ip, user, pwd):
        self.ip = ip
        self.user = user
        self.pwd = pwd

    def run_cmd(self, cmd, *args):
        """Overwrite this function.

        Place to execute a command in remote machine.

        Args:
          cmd (str): cmd line to execute

        Returns:
          str: cmd output string
        """
        # run command and get a resp string
        return ""

    def parse(self, resp, *args):
        """Overwrite this function.

        Define a parser to convert cmd response into a python obj.

        Args:
          resp (str): cmd line output

        Returns:
          obj: return a python obj
        """

        # convert resp string into python object
        return []

    def export(self, me, formatter="python"):
        if not me:
            return None

        if formatter == "xml":
            # XML resp is saved verbatim
            return me
        else:
            return json.dumps(me, sort_keys=True, indent=4 * " ")

    def by_ansible(self, subcmd, module, remote_cmd, special=False):
        """Using Ansible to access remote target to execute something.

        Args:
          ip (str): host IP address
          user (str): SSH user name
          pwd (str): SSH password (in plain text)
          module (str): Ansible module to use, default to `shell`
          remote_cmd (str): CLI to execute by ansible module inside remote target machine

        Returns:
          str: command line outpout in its raw format
        """
        # write a temporary host inventory file
        varHost = "SINGLEHOST=%s" % (self.ip)
        varUser = "SINGLEUSER=%s" % (self.user)
        varPass = "SINGLEPASS=%s" % (self.pwd)

        with NamedTemporaryFile(delete=False, mode="wt") as target:
            target.write(
                """
    all:
      hosts:
        basichost:
           ansible_host: "{{SINGLEHOST}}"
           ansible_ssh_user: "{{SINGLEUSER}}"
           ansible_ssh_pass: "{{SINGLEPASS}}"
                """
            )
        target.close()

        # run command
        cmd = [a for a in [
            "ansible",
            subcmd,
            '-i', target.name,
            '-e', varHost,
            '-e', varUser,
            '-e', varPass,
            '-m', module,
            remote_cmd] if a]

        # run ansible command
        print "Executing", " ".join(cmd)
        try:
            result = check_output(cmd)
        except CalledProcessError as e:
            print "Error when executing", e.cmd
            print e.output
            if special:
                result = e.output
            else:
                result = None

        # cleaup
        os.remove(target.name)

        # return cmd output string
        return result


class CiscoSwitchByCli:
    """Query cisco switch.

    Telnet into cicso switch and run its IOS commands
    https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/s1/sec-s1-xe-3se-5700-cr-book/sec-s1-xe-3se-5700-cr-book_chapter_010.html
    """

    def __init__(self, ip, pwd=None):
        self.session = pexpect.spawn("telnet %s" % ip)
        self.ip = ip
        self.pwd = pwd
        self.session.expect("^.*password:")
        self.session.sendline(pwd)
        self.session.expect("^.*login from host")
        self.session.sendline("\n")

    def get_mac_address(self):
        self.session.sendline("show mac")
        self.session.expect(["any other key", ".*[#]"])

        tmp = ''
        while self.session.after.strip() == "any other key":
            # print "before", self.session.before
            # print "after", self.session.after

            tmp += self.session.before
            self.session.sendline("\n")
            self.session.expect(["any other key", ".*[#>]", pexpect.EOF])

        # print 'exiting.....'
        # print "before", self.session.before
        # print "after", self.session.after
        # print "*" * 80
        tmp += self.session.after

        # strip off garbage till the mac table header.
        #
        # Sample:
        # MAC address       VLAN     Port    Trnk  State  Permanent  Openflow
        # -----------------  --------  -------  ----  -----  ---------  --------
        header = re.search("Openflow\s+(.*)", tmp).group(1)
        print "header", header

        # header is removed
        mac = re.split("%s" % header, tmp)[-1]

        # parse mac table
        mac = filter(lambda x: x, mac.split("\n"))

        # parse mac line
        mac = filter(lambda x: re.search("(\w{2}[:]){5}.*", x), mac)
        mac = map(lambda x: re.search(
            "(\w{2}[:]){5}.*", x).group(0).strip(), mac)
        return list(mac)

    def close(self):
        self.session.close()


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

    def get_setup_facts(self):
        """
        Discovery method by Ansible `setup` module.


        Returns:
          str: ansible setup dict in json
        """
        resp = self.run_cmd("", "setup", "all")
        if resp:
            tmp = "{" + "\n".join(resp.split("\n")[1:])
            return self.export(json.loads(tmp)["ansible_facts"])
        return None

    def get_vdq(self):
        """
        Discovery method by `vdq` command. `vdq` is a VSAN utility command.

        Returns:
          str: disks
        """
        resp = self.run_cmd("all", "shell", "-a vdq -q")
        if resp:
            tmp = "\n".join(resp.split("\n")[1:])
            tmp = re.sub("\s+", "", tmp)
            tmp = tmp.replace(",}", "}").replace(",]", "]")
            return self.export(json.loads(tmp))
        return None


class HostByEsxShell(RemoteDiscovery):
    """Host level discovery via ESXI cli command.

    Initialize with host's IP, user and pwd.

    Assumptions:
      1. esxi host has ssh access.
    """

    def __init__(self, ip, user, pwd):
        RemoteDiscovery.__init__(self, ip, user, pwd)

    def run_cmd(self, remote_cmd, formatter="python"):
        return self.by_ansible(subcmd="all",
                               module="shell",
                               remote_cmd="-a esxcli --debug --formatter=%s %s" % (formatter, remote_cmd))

    def run_cmd_special(self, remote_cmd, formatter="python"):
        return self.by_ansible(subcmd="all",
                               module="shell",
                               remote_cmd="-a esxcli --debug --formatter=%s %s" % (
                                   formatter, remote_cmd),
                               special=True)

    def parse_response(self, result):
        """Parse esxi CLI return string.

        Convert command line string to Python object. This is always a
        dark art to parse string depending on a format which we have
        no control. However, it is also an inevitable act when
        wrapping CLI. Ideally we should seek out for ESXI doc for
        reference or a published API.

        As of 2/9/2018, example of returned output:

        > basichost | SUCCESS | rc=0 >>
        > [
        >    {
        >       "Name"     : "naa.5000c500a0a36f3f",
        >       "VSANUUID" : "",
        >       "State"    : "Eligible for use by VSAN",
        >       "Reason"   : "None",
        >       "IsSSD"    : "0",
        >       "IsCapacityFlash": "0",
        >       "IsPDL"    : "0",
        >    },
        > ]
        """

        # print result
        # raw_input()

        # condition outpout to load it as JSON
        tmp = "\n".join(result.split("\n")[1:])

        # remove all redundant white spaces
        tmp = re.sub("\s+", "", tmp)

        # a few quirks to replace with valid JSON format
        # Alternatively, we can probably `eval` it into a python object?
        tmp = tmp.replace(",}", "}").replace(",]", "]").replace(
            "False", "false").replace("True", "true")
        # print tmp
        # raw_input()

        # return data is in format of json
        facts = json.loads(tmp)
        return facts

    def parse_response_plain(self, result):
        # condition outpout to load it as JSON
        return result

    def parse(self, resp, formatter="python"):
        if not resp:
            return None

        parsers = {
            "python": self.parse_response,
            "xml": self.parse_response_plain
        }
        return parsers[formatter](resp)

    def run(self, cmd, formatter="python"):
        return self.export(
            self.parse(
                self.run_cmd(cmd, formatter),
                formatter
            ), formatter
        )

    def runBool(self, cmd, formatter="python"):
        try:
            result = self.run_cmd_special(cmd, formatter)
            if not "Clustering is not enabled" in result and not "FAILED | rc=1" in result:
                return True
            else:
                return False
        except Exception as err:
            return False

    def get_storage_device(self):
        return self.run("storage core device list", formatter="xml")

    def get_vswitch(self):
        return self.run("network vswitch standard list")

    def get_nics(self):
        return self.run("network nic list")

    def get_route(self):
        return self.run("network ip route ipv4 list")

    def in_vsan(self):
        return self.runBool("vsan cluster get")

    def get_interface(self):
        """Retrieve networking information.

        https://pubs.vmware.com/vsphere-50/index.jsp?topic=%2Fcom.vmware.vcli.migration.doc_50%2Fcos_upgrade_technote.1.7.html
        """
        interfaces = self.parse(self.run_cmd(
            "network ip interface list"), formatter="python")
        if not interfaces:
            return None

        for i in interfaces:
            i["tags"] = self.parse(
                self.run_cmd("network ip interface tag get -i %s" % i["Name"])
            )["Tags"]

        return self.export(interfaces)
