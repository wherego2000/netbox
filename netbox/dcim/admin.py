from secrets.models import Secret

from django.apps import apps
from django.contrib import admin

from dcim.models import Device
from dcim.models import DeviceBay
from dcim.models import DeviceRole
from dcim.models import DeviceType
from dcim.models import Interface
from dcim.models import InterfaceConnection
from dcim.models import InterfaceMacTraffic
from dcim.models import InventoryItem


class DeviceRoleAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "color", "vm_role")
admin.site.register(DeviceRole, DeviceRoleAdmin)


class DeviceTypeAdmin(admin.ModelAdmin):
    list_display = ("manufacturer", "model", "part_number",
                    "u_height", "is_parent_device")
    list_filter = ("manufacturer", "is_pdu",
                   "is_network_device", "is_console_server")
admin.site.register(DeviceType, DeviceTypeAdmin)


class SecretInline(admin.StackedInline):
    model = Secret
    extra = 1


class DeviceAdmin(admin.ModelAdmin):
    list_display = ("name", "device_type", "device_role", "platform",
                    "rack", "position", "status", "primary_ip4",
                    "tenant")
    list_filter = ("device_role", "tenant", "platform", "rack", "status")
    inlines = [SecretInline]
admin.site.register(Device, DeviceAdmin)


class InterfaceAdmin(admin.ModelAdmin):
    list_display = ("name", "device", "virtual_machine", "mac_address",
                    "lag", "untagged_vlan", "type",
                    "enabled", "mgmt_only", "mode",
                    "is_trunk", "allowed_vlans")
    list_filter = ("untagged_vlan", "enabled", "is_trunk")
admin.site.register(Interface, InterfaceAdmin)


class InterfaceMacTrafficAdmin(admin.ModelAdmin):
    list_display = ("get_device", "interface", "mac_address")

    def get_device(self, obj):
        return obj.interface.device
admin.site.register(InterfaceMacTraffic, InterfaceMacTrafficAdmin)


class InterfaceConnectionAdmin(admin.ModelAdmin):
    list_display = ("interface_a", "interface_b")
admin.site.register(InterfaceConnection, InterfaceConnectionAdmin)


class DeviceBayAdmin(admin.ModelAdmin):
    list_display = ("parent_rack",
                    "parent_position",
                    "parent_ip",
                    "installed_device",
                    "child_device_role")
    list_filter = ["device__rack"]

    def parent_rack(self, obj):
        return obj.device.rack

    def parent_position(self, obj):
        return obj.device.position

    def parent_ip(self, obj):
        return obj.device.primary_ip4

    def child_device_role(self, obj):
        if obj.installed_device:
            return obj.installed_device.device_role
        else:
            return None
admin.site.register(DeviceBay, DeviceBayAdmin)


class InventoryItemAdmin(admin.ModelAdmin):
    list_display = ("device", "parent", "device_type", "manufacturer",
                    "name", "part_id", "serial", "asset_tag")
    list_filter = ("device_type", "manufacturer")
admin.site.register(InventoryItem, InventoryItemAdmin)


app = apps.get_app_config("dcim")
for model_name, model in app.models.items():
    try:
        admin.site.register(model)
    except admin.sites.AlreadyRegistered:
        pass
