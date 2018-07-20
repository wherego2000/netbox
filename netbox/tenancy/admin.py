from django.apps import apps
from django.contrib import admin

app = apps.get_app_config("tenancy")
for model_name, model in app.models.items():
    try:
        admin.site.register(model)
    except admin.sites.AlreadyRegistered:
        pass
