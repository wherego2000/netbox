# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging
import os
import pprint
import re
import sys
import uuid
from itertools import izip_longest
from subprocess import check_output
from tempfile import NamedTemporaryFile

import simplejson as json
from celery import shared_task
from celery import task
from django.contrib.auth.models import User
from django.core.files import File
from django.db.models import Q
from django.utils.text import slugify

from dcim.constants import DEVICE_STATUS_ACTIVE
from dcim.constants import DEVICE_STATUS_OFFLINE
from dcim.constants import DEVICE_STATUS_POWERED_OFF
from dcim.constants import INTERFACE_TYPE_HOST_OS
from dcim.constants import INTERFACE_TYPE_MANAGEMENT
from dcim.constants import INTERFACE_TYPE_SWITCH_PORT
from dcim.constants import SUBDEVICE_ROLE_CHILD
from dcim.discovery import BmcByCli
from dcim.discovery import HostByCli
from dcim.discovery import SwitchByCli
from dcim.models import Device
from dcim.models import DeviceBay
from dcim.models import DeviceType
from dcim.models import Interface
from dcim.models import InterfaceConnection
from dcim.models import InterfaceMacTraffic
from dcim.models import InventoryItem
from dcim.models import Manufacturer
from ipam.models import VLAN
from ipam.models import IPAddress
from netaddr import IPNetwork
from netbox.celery import app
from utilities.utils import convert_to_html_table
from virtualization.models import VirtualMachine


@app.task()
def switch_consumer(switch_id):
    """Task to poll switch for information.
    """
    switch = Device.objects.get(id=switch_id)

    if not switch.management_access:
        print "Device lacks sufficient information to access its management interface."
        return

    # try login
    discovered_name = None
    ip, secret = switch.management_access
    print "reading switch %s" % ip

    platform = re.search("cnos|enos", switch.platform.slug).group(0)
    cli = SwitchByCli(ip, secret.name, secret.password, platform)
    if not cli.connect():
        print "%s login has failed. abort." % ip
        switch.status = DEVICE_STATUS_OFFLINE
        switch.save()
        return
    else:
        switch.status = DEVICE_STATUS_ACTIVE

    # set up progress
    cli.get_mac_address(switch)
    cli.get_hostname(switch)
    cli.get_neighbors(switch)
    cli.get_system_info(switch)
    cli.dump_port_mac(switch)
    cli.get_port_info(switch)
    cli.close()
    switch.save()


@app.task
def host_get_name_consumer(host_id, is_virtual):
    if not is_virtual:
        host = Device.objects.get(id=host_id)
    else:
        host = VirtualMachine.objects.get(id=host_id)

    ip, secret = host.management_access
    resp = HostByCli(ip, secret.name, secret.password).get_hostname()

    # Sample output:
    #
    # basichost | SUCCESS | rc=0 >>
    # lmorlct0203brain3.labs.lenovo.com
    if not resp:
        host.status = DEVICE_STATUS_OFFLINE
        host.save()
        return
    else:
        host.status = DEVICE_STATUS_ACTIVE

    # (host, name) is unique
    new_name = resp.strip().split("\n")[1:][0].strip()
    if host.name != new_name:
        host.name = new_name

    # save
    host.save()


@app.task
def host_get_mac_consumer(host_id, is_virtual):
    if not is_virtual:
        host = Device.objects.get(id=host_id)
    else:
        host = VirtualMachine.objects.get(id=host_id)

    ip, secret = host.management_access
    resp = HostByCli(ip, secret.name, secret.password).get_mac()

    # Sample output:
    #
    # 8: ens4f1: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc mq state DOWN mode DEFAULT qlen 1000
    #     link/ether 90:e2:ba:e3:bc:d5 brd ff:ff:ff:ff:ff:ff
    # 9: ens5f0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc mq state DOWN mode DEFAULT qlen 1000
    #     link/ether 90:e2:ba:e3:ba:80 brd ff:ff:ff:ff:ff:ff
    #
    # We are to parse this to extract interface name and mac address
    if not resp:
        host.status = DEVICE_STATUS_OFFLINE
        host.save()
        return
    else:
        host.status = DEVICE_STATUS_ACTIVE
        host.save()

    for (name, mac, ip) in resp:
        # There are 3 scenarios interface may have been generated:
        #
        # 1. MAC could have been seen by switch. In this case, we know the MAC
        #    but doesn't know its name or host. So matching the MAC is the only option.
        #    ASSUMPTION: MAC is unique of the entire inventory.
        # 2. a repeated scan of either switch host. In this case, we should
        #    have had either a full match (name,mac,host) or None.
        #
        # Since (device,name) is unique, we have to check
        # interface carefully before creating a new one.

        # handle case #2, we have either seen a full match or none.
        aa = Interface.objects.filter(device=host,
                                      name=name,
                                      mac_address=mac)
        if aa:
            interface = aa[0]

        else:
            # search by (device,name)
            bb = Interface.objects.filter(device=host, name=name)
            if bb:
                bb.update(mac_address=mac)
            else:
                # search by (device,mac)
                cc = Interface.objects.filter(device=host,
                                              mac_address=mac)

                if cc:
                    cc.update(name=name)
                else:
                    interface = Interface(device=host, name=name,
                                          mac_address=mac)
                    interface.save()

        # create IP
        # Note that IP can be duplicate, eg. 192.168.x.x is a private
        # address, thus can be available in multiple host. So we only
        # create new IPAddress if all existing one of this address has
        # already an Interface associated w/ it.
        if ip:

            # TODO: we have to iterate all IP because
            # manual input may have used wrong **mask*.
            for e in IPAddress.objects.all():
                if ip == str(e.address.ip):
                    if e.primary_ip4_for_set.all():
                        # if it's tied to a device
                        for d in e.primary_ip4_for_set.all():
                            if d == host:
                                e.address = ip
                                e.save()

            existing_ip = IPAddress.objects.filter(address=ip, interface=interface)
            if existing_ip:
                my_ip = existing_ip[0]
            else:
                # we have create this IP, but has not associated it w/ anyone
                existing_ip = IPAddress.objects.filter(address=ip, interface__isnull=True)
                if existing_ip:
                    my_ip = existing_ip[0]
                    my_ip.interface = interface
                    my_ip.save()
                else:
                    my_ip = IPAddress(address=IPNetwork(ip), interface=interface)
                    my_ip.save()


@app.task
def server_bmc_get(device_id):
    """To group all `get_` calls.

    It turned out that BMC only allows **1** SSH session
    at a time. The consequetive SSH call will return an error

    ```
    X11 forwarding request failed on channel 0
    Connection to 10.240.41.254 closed.
    ```

    Args:
      device_id: host server id. This device should have a property `bmc_access`
        which has BMC (ip, secret). We are **ASSUMING** that a device has ONE BMC.
    """
    server = Device.objects.get(id=device_id)
    the_bmc = server.bmc_controllers[0]

    ip, secret = server.bmc_access
    print "reading server %s BMC name" % ip

    cli = BmcByCli(ip, secret.name, secret.password)

    if not cli.connect():
        print "Access to BMC %s has failed. abort." % ip
        the_bmc.status = DEVICE_STATUS_OFFLINE
        server.save()
        the_bmc.save()
        return
    else:
        the_bmc.status = DEVICE_STATUS_ACTIVE

    # server name
    # Example output:
    #
    # ```
    # SystemName: brain4-3
    # ContactPerson:
    # Location:
    # FullPostalAddress:
    # RoomID:
    # RackID:
    # LowestU: 0
    # HeightU: 2
    # ```
    #
    # This is the name by BMC, not FQDN or hostname that OS represents.
    name = filter(lambda x: "SystemName" in x, cli.get_name().split("\n"))
    name = re.search("SystemName:(?P<name>.+)", name[0]).group("name").strip()
    if not server.name:
        server.name = name

    the_bmc.name = "%s BMC" % name

    # eth0 mac
    # Example output:
    #
    # ```
    # -b      :  08:94:ef:48:13:3d
    # ```
    mac = cli.get_eth0_mac()
    mac = re.search("b\s+:(?P<mac>.*)", mac).group("mac").strip().upper()
    existings = Interface.objects.filter(mac_address=mac)
    if existings:
        i = existings[0]
    else:
        i = Interface(device=server)

    i.device = the_bmc
    i.name = "eth0"
    i.type = INTERFACE_TYPE_MANAGEMENT
    i.mgmt_only = True
    i.mac_address = mac
    i.save()

    # link Interface to its primary IP
    the_bmc.primary_ip4.interface = i
    the_bmc.primary_ip4.save()

    # vpd sys
    # To get serial number, uuid of this device.
    #
    # Example output:
    # ```
    # Machine Type-Model             Serial Number                  UUID
    # --------------                 ---------                      ----
    # 8871AC1                        J11PGTT                        60CD7A22827E11E79D09089    # ```
    tmp = re.split("-+", cli.get_vpd_sys())
    sys_info = re.split("\s+", tmp[-1].strip())[:3]

    the_bmc.serial = ""
    the_bmc.asset_tag = ""
    the_bmc.save()

    server.serial = sys_info[1]
    if server.asset_tag != sys_info[2]:
        if Device.objects.filter(asset_tag=sys_info[2]):
            # wow we have someone who already owned this tag!
            # Create a random uuid one.
            server.asset_tag = "Generated %s" % str(uuid.uuid4())
        else:
            server.asset_tag = sys_info[2]
    server.save()

    server.device_type.part_number = sys_info[0]
    server.device_type.save()

    # get server's power state
    power = filter(lambda x: "power" in x, cli.get_name().split("\n"))
    for p in power:
        state = re.search("power\s(?P<state>.+)", power).group("state").strip()
        if state == "off":
            server.status = DEVICE_STATUS_POWERED_OFF
        elif state == "on":
            # Note: server BMC indicates `power on`, but OS may still
            # be in off state.
            pass
    server.save()

    # dump raid controllers inside server
    for c in cli.get_storage_controllers():
        # manufacturer
        m, whatever = Manufacturer.objects.get_or_create(
            name=c["manufacturer"].strip(),
            slug=c["manufacturer"].lower().strip()
        )

        # device type
        model = c["model"]
        existing = DeviceType.objects.filter(
            slug=slugify(model)
        )
        if existing:
            dt = existing[0]
        else:
            dt, whatever = DeviceType.objects.get_or_create(
                manufacturer=m,
                model=model,
                slug=slugify(model),
                part_number=c["part_id"].strip(),
                u_height=0,  # TODO: hardcoded special value!
                is_network_device=False,
                subdevice_role=SUBDEVICE_ROLE_CHILD
            )

        # items
        asset_tag = c["asset_tag"].strip()
        serial = c["serial"].strip()
        if not asset_tag:
            existing = InventoryItem.objects.filter(
                asset_tag=asset_tag
            )
        else:
            existing = InventoryItem.objects.filter(
                serial=serial
            )

        if existing:
            item = existing[0]
        else:  # inventory item
            item = InventoryItem(
                device=server,
                manufacturer=m,
                discovered=True,
                asset_tag=c["asset_tag"].strip(),

            )

        item.device_type = dt
        item.name = c["target"]
        item.part_id = c["part_id"].strip()
        item.serial = c["serial"].strip()
        item.description = convert_to_html_table(c["description"], ":")
        item.save()

    # dump disks inside server
    for c in cli.get_storage_drives():
        # manufacturer
        m, whatever = Manufacturer.objects.get_or_create(
            name=c["manufacturer"].strip(),
            slug=c["manufacturer"].lower().strip()
        )

        # device type
        model = "/".join(filter(lambda x: x,
                                [c["name"], c["disk_type"], c["media_type"]]))
        existing = DeviceType.objects.filter(
            slug=slugify(model)
        )
        if existing:
            dt = existing[0]
        else:
            dt, whatever = DeviceType.objects.get_or_create(
                manufacturer=m,
                model=model,
                slug=slugify(model),
                part_number=c["part_id"].strip(),
                u_height=0,  # TODO: hardcoded special value!
                is_network_device=False,
                subdevice_role=SUBDEVICE_ROLE_CHILD
            )

        # inventory item
        item, whatever = InventoryItem.objects.get_or_create(
            device=server,
            manufacturer=m,
            device_type=dt,
            discovered=True,
            name=c["target"],
            part_id=c["part_id"].strip(),
            serial=c["serial"].strip(),
        )
        item.description = convert_to_html_table(c["description"], ":")
        item.save()

    # dump fw
    tmp = cli.get_firmware_status()
    tmp = re.sub("-", "", tmp)
    item, whatever = InventoryItem.objects.get_or_create(
        device=server,
        name="firmware",
        discovered=True,
    )
    item.description = convert_to_html_table(tmp)
    item.save()


@app.task
def update_device_switch_connection():
    """Update interface connections.

    There are two type of connections:
    1. switch - switch
    2. device - switch

    switch-switch is being handled when polling switch. Here we
    update device-switch connection.
    """

    for me in Interface.objects.all():
        for the_remote in me.direct_switch_connections:
            if not InterfaceConnection.objects.filter(
                Q(interface_a=me, interface_b=the_remote) |
                Q(interface_a=the_remote, interface_b=me)
            ):
                InterfaceConnection(
                    interface_a=me,
                    interface_b=the_remote
                ).save()


@app.task
def device_bmc_power_consumer(device_id, state):
    """Control device power via BMC interface.

    Args:
      id (int): device ID.
      state (int): values from BMC_POWER_CHOICES.
    """
    server = Device.objects.get(id=device_id)
    if not server.bmc_controllers:
        print "%s has not BMC controller. skip." % ip
        return

    the_bmc = server.bmc_controllers[0]

    ip, secret = server.bmc_access
    print "reading server %s BMC name" % ip

    cli = BmcByCli(ip, secret.name, secret.password)

    if not cli.connect():
        print "Access to BMC %s has failed. abort." % ip
        the_bmc.status = DEVICE_STATUS_OFFLINE
        server.save()
        the_bmc.save()
        return
    else:
        the_bmc.status = DEVICE_STATUS_ACTIVE
    the_bmc.save()

    cli.set_power_state(int(state))
