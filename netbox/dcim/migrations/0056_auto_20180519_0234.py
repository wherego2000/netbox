# -*- coding: utf-8 -*-
# Generated by Django 1.11.13 on 2018-05-19 02:34
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dcim', '0055_virtualchassis_ordering'),
    ]

    operations = [
        migrations.AlterField(
            model_name='devicetype',
            name='subdevice_role',
            field=models.NullBooleanField(choices=[(None, 'None'), (True, 'Parent'), (False, 'Child')], default=None,
                                          help_text='Parent devices house child devices in device bays. Select          "None" if this device type is neither a parent nor a child.', verbose_name='Parent/child status'),
        ),
    ]
