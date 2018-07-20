# -*- coding: utf-8 -*-
# Generated by Django 1.9.7 on 2016-06-28 17:21
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dcim', '0002_auto_20160622_1821'),
    ]

    operations = [
        migrations.AlterField(
            model_name='interface',
            name='form_factor',
            field=models.PositiveSmallIntegerField(choices=[[0, b'Virtual'], [800, b'10/100M (100BASE-TX)'], [1000, b'1GE (1000BASE-T)'], [
                                                   1100, b'1GE (SFP)'], [1150, b'10GE (10GBASE-T)'], [1200, b'10GE (SFP+)'], [1300, b'10GE (XFP)'], [1400, b'40GE (QSFP+)']], default=1200),
        ),
        migrations.AlterField(
            model_name='interfacetemplate',
            name='form_factor',
            field=models.PositiveSmallIntegerField(choices=[[0, b'Virtual'], [800, b'10/100M (100BASE-TX)'], [1000, b'1GE (1000BASE-T)'], [
                                                   1100, b'1GE (SFP)'], [1150, b'10GE (10GBASE-T)'], [1200, b'10GE (SFP+)'], [1300, b'10GE (XFP)'], [1400, b'40GE (QSFP+)']], default=1200),
        ),
    ]
