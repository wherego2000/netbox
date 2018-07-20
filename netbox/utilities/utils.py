from __future__ import unicode_literals

import datetime

import simplejson as json
import six
from django.http import HttpResponse
from django.urls import reverse


def csv_format(data):
    """
    Encapsulate any data which contains a comma within double quotes.
    """
    csv = []
    for value in data:

        # Represent None or False with empty string
        if value is None or value is False:
            csv.append('')
            continue

        # Convert dates to ISO format
        if isinstance(value, (datetime.date, datetime.datetime)):
            value = value.isoformat()

        # Force conversion to string first so we can check for any commas
        if not isinstance(value, six.string_types):
            value = '{}'.format(value)

        # Double-quote the value if it contains a comma
        if ',' in value or '\n' in value:
            csv.append('"{}"'.format(value))
        else:
            csv.append('{}'.format(value))

    return ','.join(csv)


def queryset_to_csv(queryset):
    """
    Export a queryset of objects as CSV, using the model's to_csv() method.
    """
    output = []

    # Start with the column headers
    headers = ','.join(queryset.model.csv_headers)
    output.append(headers)

    # Iterate through the queryset
    for obj in queryset:
        data = csv_format(obj.to_csv())
        output.append(data)

    # Build the HTTP response
    response = HttpResponse(
        '\n'.join(output),
        content_type='text/csv'
    )
    filename = 'netbox_{}.csv'.format(queryset.model._meta.verbose_name_plural)
    response['Content-Disposition'] = 'attachment; filename="{}"'.format(
        filename)

    return response


def foreground_color(bg_color):
    """
    Return the ideal foreground color (black or white) for a given
    background color in hexadecimal RGB format.
    """
    bg_color = bg_color.strip('#')
    r, g, b = [int(bg_color[c:c + 2], 16) for c in (0, 2, 4)]
    if r * 0.299 + g * 0.587 + b * 0.114 > 186:
        return '000000'
    else:
        return 'ffffff'


def convert_to_html_table(blob, separator=None):
    """Convert CLI output string into a HTML table.

    Input blob is a multiline string and each field is separated by a
    `separator`, eg. CSV.

    Args:
      blog (string): input to convert.
      separator (string): separator to use.

    Returns:
      string: a HTML string. Displaying it should use `|safe` in template.
    """
    description = ""
    for line in blob.strip().split("\n"):
        if not line.strip():
            continue

        tmp = ""
        for x in line.split(separator):
            tmp += "<td>%s</td>" % x
        description += "<tr>%s</tr>" % tmp
    description = '<table class="table table-hover table-condensed">%s</table>' % description
    return description


def draw_device_cytoscape(device):
    """Helper to create Cytoscape json representation of a Device object.

    Args:
      device (Device obj): A Device object to draw.

    Returns:
      json: JSON data formatted for cytoscape to render its graph.
    """

    if hasattr(device, "parent_bay"):
        a = device.parent_bay.device
    else:
        a = device

    device_role = a.device_role.slug.lower()
    if "switch" in device_role:
        a_role = "switch"
    else:
        a_role = "server"

    return (a.id, a_role,
            {
                "id": "device%d" % a.id,
                "label": a.name,
                "type": a_role,
                "href": reverse("dcim:device",
                                kwargs={"pk": a.id})
            })


def draw_interface_cytoscape(device_id, device_role, interface):
    """Helper to create Cytoscape json representation of an Interface object.

    Args:
      device_id (str): ID of the device that contains this interface.
      device_role (str): role of device. We will draw `port` if device
        is a switch, and `in terface` if it's a server.
      interface (Interface obj): An Interface object to draw.

    Returns:
      json: JSON data formatted for cytoscape to render its graph.
    """

    # draw interfaces
    label = interface.name
    if device_role == "switch":
        a_conn_type = "port"
    elif device_role == "server":
        a_conn_type = "interface"
        if hasattr(interface.device, "parent_bay"):
            tmp = interface.device.device_role.slug.lower()
            if 'bmc' in tmp:
                a_conn_type = "bmc"
                label = "BMC"
    else:
        a_conn_type = "interface"
    return (interface.id, a_conn_type,
            {
                "id": "port%d" % interface.id,
                "label": label,
                "type": a_conn_type,
                "parent": "device%d" % device_id,
                "href": reverse("dcim:interface",
                                kwargs={"pk": interface.id})
            })


def draw_level_2_interface_connections_cytoscape(connections):
    """Utility function to draw L2 connection diagram in cytoscape format.

    Args:
      connections: queryset of dcim.InterfaceConnection.

    Returns:
      json: JSON data formatted for cytoscape to render its graph.
    """
    nodes = edges = []
    for l in connections.filter(interface_a__device__isnull=False,
                                interface_b__device__isnull=False):

        a_id, a_role, data = draw_device_cytoscape(l.interface_a.device)
        nodes.append({"data": data})
        b_id, b_role, data = draw_device_cytoscape(l.interface_b.device)
        nodes.append({"data": data})


def draw_level_1_interface_connections_cytoscape(connections):
    """Utility function to draw L1 connection diagram in cytoscape format.

    Args:
      connections: queryset of dcim.InterfaceConnection.

    Returns:
      json: JSON data formatted for cytoscape to render its graph.
    """
    nodes = edges = []
    for l in connections.filter(interface_a__device__isnull=False,
                                interface_b__device__isnull=False):
        a_id, a_role, data = draw_device_cytoscape(l.interface_a.device)
        nodes.append({"data": data})
        b_id, b_role, data = draw_device_cytoscape(l.interface_b.device)
        nodes.append({"data": data})

        a_inter_id, a_inter_type, data = draw_interface_cytoscape(a_id, a_role,
                                                                  l.interface_a)
        nodes.append({"data": data})
        b_inter_id, b_inter_type, data = draw_interface_cytoscape(b_id, b_role,
                                                                  l.interface_b)
        nodes.append({"data": data})

        # link interfaces
        edges.append({
            "data": {
                "id": "port%d_to_port%d" % (a_inter_id, b_inter_id),
                "source": "port%d" % a_inter_id,
                "target": "port%d" % b_inter_id,
            },
        })
    return json.dumps(nodes + edges)


def draw_level_1_interface_connections_netjson(connections):
    """Utility function to draw L1 connection diagram in NetJSON format.

    Args:
      connections: queryset of dcim.InterfaceConnection.

    Returns:
      json: JSON data formatted in NetJSON to render its graph.
    """

    nodes = []
    links = []

    # draw all device nodes
    devices = []
    for d in connections.filter(interface_a__device__isnull=False,
                                interface_b__device__isnull=False):
        devices.append(d.interface_a.device)
        devices.append(d.interface_b.device)
    for d in set(devices):
        try:
            devices.append(d.parent_bay.device)
        except:
            pass

    nodes += [draw_device_netjson(x) for x in set(devices)]

    # draw bay device -> parent link
    for d in set(devices):
        if hasattr(d, "parent_bay"):
            links.append({
                "source": "device%d" % d.parent_bay.device.id,
                "target": "device%d" % d.id,
                "cost": 100,
                "properties": {
                    "type": "device-to-device"
                }

            })

    # draw all interface nodes
    interfaces = []
    for c in connections:
        interfaces.append(c.interface_a)
        interfaces.append(c.interface_b)
    for i in set(interfaces):
        if hasattr(i.device, "parent_bay"):
            # A bay device. skip it's own interface.
            continue

        node, link = draw_interface_netjson(i)
        nodes.append(node)
        links.append(link)

    # # draw interface-interface connections
    for c in connections:
        if hasattr(c.interface_a.device, "parent_bay"):
            a = c.interface_a.device
            a_label = "device"
        else:
            a = c.interface_a
            a_label = "interface"

        if hasattr(c.interface_b.device, "parent_bay"):
            b = c.interface_b.device
            b_label = "device"
        else:
            b = c.interface_b
            b_label = "interface"

        links.append({
            "source": "%s%d" % (a_label, a.id),
            "target": "%s%d" % (b_label, b.id),
            "cost": 1,
        })

    return {
        "type": "NetworkGraph",
        "protocol": "static",
        "version": None,
        "metric": None,
        "label": "Device connections",
        "nodes": nodes,
        "links": links
    }


def draw_device_netjson(device):
    """Helper to create NetJSON data payload.

    NetJSON (http://netjson.org/docs/implementations.html) seems promising
    to describe network topology.
    """

    return {
        "id": "device%d" % device.id,
        "label": device.name,
        "local_addresses": [
            str(device.primary_ip4)
        ],
        "properties": {
            "status": device.status,
            "type": device.device_role.slug,
            "href": reverse("dcim:device",
                            kwargs={"pk": device.id})
        }
    }


def draw_interface_netjson(interface):
    """Helper to create NetJSON data payload for inteface.
    """
    node = {
        "id": "interface%d" % interface.id,
        "label": "%s\n%s" % (interface.name, interface.mac_address),
        "local_addresses": [
            str(interface.mac_address),
        ],
        "properties": {
            "href": reverse("dcim:interface",
                            kwargs={"pk": interface.id})
        }
    }
    link = {
        "source": "device%d" % interface.device.id,
        "target": "interface%d" % interface.id,
        "cost": 0.5
    }

    return node, link
