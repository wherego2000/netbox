from django.apps import apps
from django.contrib import admin

from ipam.models import IPAddress


class IPAddressAdmin(admin.ModelAdmin):
    list_display = ("address", "interface", "status",
                    "parent_device", "family",
                    "tenant", "role")
    list_filter = ("tenant", "role")

    def parent_device(self, obj):
        if obj.interface:
            return obj.interface.device
        else:
            return None

admin.site.register(IPAddress, IPAddressAdmin)

app = apps.get_app_config("ipam")
for model_name, model in app.models.items():
    try:
        admin.site.register(model)
    except admin.sites.AlreadyRegistered:
        pass
