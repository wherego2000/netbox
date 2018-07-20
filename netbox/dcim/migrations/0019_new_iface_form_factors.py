# -*- coding: utf-8 -*-
# Generated by Django 1.10 on 2016-09-13 15:20
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dcim', '0018_device_add_asset_tag'),
    ]

    operations = [
        migrations.AlterField(
            model_name='interface',
            name='form_factor',
            field=models.PositiveSmallIntegerField(choices=[[b'Virtual interfaces', [[0, b'Virtual']]], [b'Ethernet (fixed)', [[800, b'100BASE-TX (10/100ME)'], [1000, b'1000BASE-T (1GE)'], [1150, b'10GBASE-T (10GE)']]], [b'Ethernet (modular)', [[1050, b'GBIC (1GE)'], [1100, b'SFP (1GE)'], [1200, b'SFP+ (10GE)'], [1300, b'XFP (10GE)'], [1310, b'XENPAK (10GE)'], [1320, b'X2 (10GE)'], [1350, b'SFP28 (25GE)'], [1400, b'QSFP+ (40GE)'], [1500, b'CFP (100GE)'], [
                                                   1600, b'QSFP28 (100GE)']]], [b'FibreChannel', [[3010, b'SFP (1GFC)'], [3020, b'SFP (2GFC)'], [3040, b'SFP (4GFC)'], [3080, b'SFP+ (8GFC)'], [3160, b'SFP+ (16GFC)']]], [b'Serial', [[4000, b'T1 (1.544 Mbps)'], [4010, b'E1 (2.048 Mbps)'], [4040, b'T3 (45 Mbps)'], [4050, b'E3 (34 Mbps)']]], [b'Stacking', [[5000, b'Cisco StackWise'], [5050, b'Cisco StackWise Plus']]], [b'Other', [[32767, b'Other']]]], default=1200),
        ),
        migrations.AlterField(
            model_name='interfacetemplate',
            name='form_factor',
            field=models.PositiveSmallIntegerField(choices=[[b'Virtual interfaces', [[0, b'Virtual']]], [b'Ethernet (fixed)', [[800, b'100BASE-TX (10/100ME)'], [1000, b'1000BASE-T (1GE)'], [1150, b'10GBASE-T (10GE)']]], [b'Ethernet (modular)', [[1050, b'GBIC (1GE)'], [1100, b'SFP (1GE)'], [1200, b'SFP+ (10GE)'], [1300, b'XFP (10GE)'], [1310, b'XENPAK (10GE)'], [1320, b'X2 (10GE)'], [1350, b'SFP28 (25GE)'], [1400, b'QSFP+ (40GE)'], [1500, b'CFP (100GE)'], [
                                                   1600, b'QSFP28 (100GE)']]], [b'FibreChannel', [[3010, b'SFP (1GFC)'], [3020, b'SFP (2GFC)'], [3040, b'SFP (4GFC)'], [3080, b'SFP+ (8GFC)'], [3160, b'SFP+ (16GFC)']]], [b'Serial', [[4000, b'T1 (1.544 Mbps)'], [4010, b'E1 (2.048 Mbps)'], [4040, b'T3 (45 Mbps)'], [4050, b'E3 (34 Mbps)']]], [b'Stacking', [[5000, b'Cisco StackWise'], [5050, b'Cisco StackWise Plus']]], [b'Other', [[32767, b'Other']]]], default=1200),
        ),
    ]
