# -*- coding: utf-8 -*-
# Generated by Django 1.11.13 on 2018-05-25 01:12
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('virtualization', '0004_virtualmachine_add_role'),
        ('dcim', '0064_auto_20180525_0056'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='interface',
            unique_together=set([('virtual_machine', 'name', 'mac_address'), ('device', 'name', 'mac_address')]),
        ),
    ]
