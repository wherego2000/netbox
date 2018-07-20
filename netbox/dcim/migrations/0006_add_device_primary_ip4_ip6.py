# -*- coding: utf-8 -*-
# Generated by Django 1.9.7 on 2016-07-11 18:40
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('ipam', '0001_initial'),
        ('dcim', '0005_auto_20160706_1722'),
    ]

    operations = [
        migrations.AddField(
            model_name='device',
            name='primary_ip4',
            field=models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                                       related_name='primary_ip4_for', to='ipam.IPAddress', verbose_name=b'Primary IPv4'),
        ),
        migrations.AddField(
            model_name='device',
            name='primary_ip6',
            field=models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                                       related_name='primary_ip6_for', to='ipam.IPAddress', verbose_name=b'Primary IPv6'),
        ),
    ]
