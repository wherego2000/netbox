# -*- coding: utf-8 -*-
# Generated by Django 1.10 on 2016-08-11 15:42
from __future__ import unicode_literals

from django.db import migrations
import utilities.fields


class Migration(migrations.Migration):

    dependencies = [
        ('dcim', '0017_rack_add_role'),
    ]

    operations = [
        migrations.AddField(
            model_name='device',
            name='asset_tag',
            field=utilities.fields.NullableCharField(
                blank=True, help_text=b'A unique tag used to identify this device', max_length=50, null=True, unique=True, verbose_name=b'Asset tag'),
        ),
    ]
