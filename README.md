This is a fork of [NetBox](https://github.com/digitalocean/netbox)
project that we are to experiment for:

1. phase 1: infrastructure inventory &mdash; rack, server, switch,
   PDU, cabling.
2. phase 2: network connection diagnosis
3. phase 3: design vs. reality
4. phase 4: continuous monitoring & alert
5. phase 5: design &rarr; reality

# Background

It has been a painful experience to witness how we are diagnosing
infrastructure, especially network connections, in a what I would call
`chasing the rabbit` fashion in which `ping`, `route`, `vlan`, `port`
on a switch, to which port the two ends of a cable plugged into, all
coming to a single chain of a `valid` connection. Part of it is to
verify hardware connections (cablings), part of software
configurations (many layers deep). A knowledgeable person can traverse
the link from one end to the other, but even he is faced with a harsh
reality of which area is to focus on.

If you think of it in the highest level &mdash; a topology design, its
mirror image is the reality. Scanning devices to acquire and compose
the reality is what computer is good at. Therefore, like counting
inventory, it shall have the capability to **replace** the typing of
repetitive commands by a human hand, and piece-meal ocean of meta data
into a **logical, meaningful view** that saves operator mechanical
efforts. Without knowing the design, at least it should produce, and
even maintain, the reality view, on demand and continuously.

Taking this further, if reality can be described, the same syntax
shall be used to describe **expectation** (design). Now, we will be
equiped with both views and produce a **diff** &rarr; Previously we
are relying on an experienced operator to know where to look; in the
future this diff view highlights it, color-codes it, for anyone who
wants to look, anytime, and no devop expertise required.

Sky is the limit, but this doesn't mean much. Practically speaking,
phase 1-5 draws a picture that shifts the focus of infrastructure
management from counting inventory to knowledge automation. The goal
is not to eliminate human factor, but to alleviate waste of their
bandwidth on things that can be well known, well modeled, and scriptable.

Analysis requires intelligence; SSH to ten machines does not.

![NetBox](docs/netbox_logo.png "NetBox logo")

NetBox is an IP address management (IPAM) and data center infrastructure
management (DCIM) tool. Initially conceived by the network engineering team at
[DigitalOcean](https://www.digitalocean.com/), NetBox was developed specifically
to address the needs of network and infrastructure engineers.

NetBox runs as a web application atop the [Django](https://www.djangoproject.com/)
Python framework with a [PostgreSQL](http://www.postgresql.org/) database. For a
complete list of requirements, see `requirements.txt`. The code is available [on GitHub](https://github.com/digitalocean/netbox).

The complete documentation for NetBox can be found at [Read the Docs](http://netbox.readthedocs.io/en/stable/).

Questions? Comments? Please subscribe to [the netbox-discuss mailing list](https://groups.google.com/forum/#!forum/netbox-discuss),
or join us in the #netbox Slack channel on [NetworkToCode](https://networktocode.slack.com/)!

### Build Status

NetBox is built against both Python 2.7 and 3.5.  Python 3.5 is recommended.

|             | status |
|-------------|------------|
| **master** | [![Build Status](https://travis-ci.org/digitalocean/netbox.svg?branch=master)](https://travis-ci.org/digitalocean/netbox) |
| **develop** | [![Build Status](https://travis-ci.org/digitalocean/netbox.svg?branch=develop)](https://travis-ci.org/digitalocean/netbox) |

## Screenshots

![Screenshot of main page](docs/media/screenshot1.png "Main page")

![Screenshot of rack elevation](docs/media/screenshot2.png "Rack elevation")

![Screenshot of prefix hierarchy](docs/media/screenshot3.png "Prefix hierarchy")

# Installation

Please see [the documentation](http://netbox.readthedocs.io/en/stable/) for
instructions on installing NetBox. To upgrade NetBox, please download the [latest release](https://github.com/digitalocean/netbox/releases)
and run `upgrade.sh`.

## Alternative Installations

* [Docker container](https://github.com/ninech/netbox-docker) (via [@cimnine](https://github.com/cimnine))
* [Vagrant deployment](https://github.com/ryanmerolle/netbox-vagrant) (via [@ryanmerolle](https://github.com/ryanmerolle))
* [Ansible deployment](https://github.com/lae/ansible-role-netbox) (via [@lae](https://github.com/lae))
