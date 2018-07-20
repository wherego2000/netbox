from __future__ import absolute_import

import os

from celery import Celery
from django.apps import apps
from django.conf import settings

# set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netbox.settings')

app = Celery('netbox')

# Using a string here means the worker will not have to
# pickle the object when using Windows.
app.config_from_object('django.conf:settings')
print settings.INSTALLED_APPS

#app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)

app.autodiscover_tasks(lambda: [n.name for n in apps.get_app_configs()])


@app.task(bind=True)
def debug_task(self):
    print('Request: {0!r}'.format(self.request))
