# -*- coding: utf-8 -*-
# Generated by Django 1.11.13 on 2018-05-19 02:41
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('dcim', '0056_auto_20180519_0234'),
        ('secrets', '0004_secret_password'),
    ]

    operations = [
        migrations.AddField(
            model_name='secret',
            name='interface',
            field=models.ForeignKey(
                blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='dcim.Interface'),
        ),
    ]