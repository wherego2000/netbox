# -*- coding: utf-8 -*-
# Generated by Django 1.11.13 on 2018-05-25 01:52
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('ipam', '0021_vrf_ordering'),
    ]

    operations = [
        migrations.AlterField(
            model_name='ipaddress',
            name='interface',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='ip_addresses', to='dcim.Interface'),
        ),
    ]
