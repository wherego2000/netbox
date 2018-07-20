# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2017-05-24 15:34
from __future__ import unicode_literals

import dcim.fields
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('circuits', '0008_circuittermination_interface_protect_on_delete'),
    ]

    operations = [
        migrations.AlterField(
            model_name='circuit',
            name='cid',
            field=models.CharField(max_length=50, verbose_name='Circuit ID'),
        ),
        migrations.AlterField(
            model_name='circuit',
            name='commit_rate',
            field=models.PositiveIntegerField(
                blank=True, null=True, verbose_name='Commit rate (Kbps)'),
        ),
        migrations.AlterField(
            model_name='circuit',
            name='install_date',
            field=models.DateField(blank=True, null=True,
                                   verbose_name='Date installed'),
        ),
        migrations.AlterField(
            model_name='circuittermination',
            name='port_speed',
            field=models.PositiveIntegerField(
                verbose_name='Port speed (Kbps)'),
        ),
        migrations.AlterField(
            model_name='circuittermination',
            name='pp_info',
            field=models.CharField(
                blank=True, max_length=100, verbose_name='Patch panel/port(s)'),
        ),
        migrations.AlterField(
            model_name='circuittermination',
            name='term_side',
            field=models.CharField(
                choices=[('A', 'A'), ('Z', 'Z')], max_length=1, verbose_name='Termination'),
        ),
        migrations.AlterField(
            model_name='circuittermination',
            name='upstream_speed',
            field=models.PositiveIntegerField(
                blank=True, help_text='Upstream speed, if different from port speed', null=True, verbose_name='Upstream speed (Kbps)'),
        ),
        migrations.AlterField(
            model_name='circuittermination',
            name='xconnect_id',
            field=models.CharField(
                blank=True, max_length=50, verbose_name='Cross-connect ID'),
        ),
        migrations.AlterField(
            model_name='provider',
            name='account',
            field=models.CharField(
                blank=True, max_length=30, verbose_name='Account number'),
        ),
        migrations.AlterField(
            model_name='provider',
            name='admin_contact',
            field=models.TextField(blank=True, verbose_name='Admin contact'),
        ),
        migrations.AlterField(
            model_name='provider',
            name='asn',
            field=dcim.fields.ASNField(
                blank=True, null=True, verbose_name='ASN'),
        ),
        migrations.AlterField(
            model_name='provider',
            name='noc_contact',
            field=models.TextField(blank=True, verbose_name='NOC contact'),
        ),
        migrations.AlterField(
            model_name='provider',
            name='portal_url',
            field=models.URLField(blank=True, verbose_name='Portal'),
        ),
    ]
