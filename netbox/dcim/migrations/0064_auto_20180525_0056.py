# -*- coding: utf-8 -*-
# Generated by Django 1.11.13 on 2018-05-25 00:56
from __future__ import unicode_literals

import dcim.fields
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('virtualization', '0004_virtualmachine_add_role'),
        ('dcim', '0063_auto_20180524_0205'),
    ]

    operations = [
        migrations.AlterField(
            model_name='interface',
            name='mac_address',
            field=dcim.fields.MACAddressField(blank=True, null=True, verbose_name='MAC Address'),
        ),
        migrations.AlterUniqueTogether(
            name='interface',
            unique_together=set([('virtual_machine', 'mac_address'), ('device', 'mac_address')]),
        ),
    ]
