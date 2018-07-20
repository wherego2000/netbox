# -*- coding: utf-8 -*-
# Generated by Django 1.11.13 on 2018-05-25 14:03
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('virtualization', '0004_virtualmachine_add_role'),
        ('dcim', '0065_auto_20180525_0112'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='interface',
            unique_together=set([('virtual_machine', 'name'), ('device', 'name')]),
        ),
    ]