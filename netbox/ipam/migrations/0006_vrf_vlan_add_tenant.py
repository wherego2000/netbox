# -*- coding: utf-8 -*-
# Generated by Django 1.9.8 on 2016-07-27 14:39
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('tenancy', '0001_initial'),
        ('ipam', '0005_auto_20160725_1842'),
    ]

    operations = [
        migrations.AddField(
            model_name='vlan',
            name='tenant',
            field=models.ForeignKey(
                blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='vlans', to='tenancy.Tenant'),
        ),
        migrations.AddField(
            model_name='vrf',
            name='tenant',
            field=models.ForeignKey(
                blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='vrfs', to='tenancy.Tenant'),
        ),
    ]
