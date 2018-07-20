# -*- coding: utf-8 -*-
# Generated by Django 1.9.8 on 2016-08-10 14:58
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('dcim', '0016_module_add_manufacturer'),
    ]

    operations = [
        migrations.CreateModel(
            name='RackRole',
            fields=[
                ('id', models.AutoField(auto_created=True,
                                        primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=50, unique=True)),
                ('slug', models.SlugField(unique=True)),
                ('color', models.CharField(choices=[[b'teal', b'Teal'], [b'green', b'Green'], [b'blue', b'Blue'], [b'purple', b'Purple'], [b'yellow', b'Yellow'], [
                 b'orange', b'Orange'], [b'red', b'Red'], [b'light_gray', b'Light Gray'], [b'medium_gray', b'Medium Gray'], [b'dark_gray', b'Dark Gray']], max_length=30)),
            ],
            options={
                'ordering': ['name'],
            },
        ),
        migrations.AddField(
            model_name='rack',
            name='role',
            field=models.ForeignKey(
                blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='racks', to='dcim.RackRole'),
        ),
    ]
