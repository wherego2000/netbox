from __future__ import unicode_literals

from django.contrib.auth.mixins import PermissionRequiredMixin
from django.db.models import Count
from django.db.models import Q
from django.shortcuts import get_object_or_404
from django.shortcuts import render
from django.urls import reverse
from django.views.generic import View

from circuits.models import Circuit
from dcim.models import Device
from dcim.models import InterfaceConnection
from dcim.models import Rack
from dcim.models import RackReservation
from dcim.models import Site
from ipam.models import VLAN
from ipam.models import VRF
from ipam.models import IPAddress
from ipam.models import Prefix
from utilities.utils import draw_level_1_interface_connections_cytoscape
from utilities.views import BulkDeleteView
from utilities.views import BulkEditView
from utilities.views import BulkImportView
from utilities.views import ObjectDeleteView
from utilities.views import ObjectEditView
from utilities.views import ObjectListView
from virtualization.models import VirtualMachine

from . import filters
from . import forms
from . import tables
from .models import Tenant
from .models import TenantGroup

#
# Tenant groups
#


class TenantGroupListView(ObjectListView):
    queryset = TenantGroup.objects.annotate(tenant_count=Count('tenants'))
    table = tables.TenantGroupTable
    template_name = 'tenancy/tenantgroup_list.html'


class TenantGroupCreateView(PermissionRequiredMixin, ObjectEditView):
    permission_required = 'tenancy.add_tenantgroup'
    model = TenantGroup
    model_form = forms.TenantGroupForm

    def get_return_url(self, request, obj):
        return reverse('tenancy:tenantgroup_list')


class TenantGroupEditView(TenantGroupCreateView):
    permission_required = 'tenancy.change_tenantgroup'


class TenantGroupBulkImportView(PermissionRequiredMixin, BulkImportView):
    permission_required = 'tenancy.add_tenantgroup'
    model_form = forms.TenantGroupCSVForm
    table = tables.TenantGroupTable
    default_return_url = 'tenancy:tenantgroup_list'


class TenantGroupBulkDeleteView(PermissionRequiredMixin, BulkDeleteView):
    permission_required = 'tenancy.delete_tenantgroup'
    cls = TenantGroup
    queryset = TenantGroup.objects.annotate(tenant_count=Count('tenants'))
    table = tables.TenantGroupTable
    default_return_url = 'tenancy:tenantgroup_list'


#
#  Tenants
#

class TenantListView(ObjectListView):
    queryset = Tenant.objects.select_related('group')
    filter = filters.TenantFilter
    filter_form = forms.TenantFilterForm
    table = tables.TenantTable
    template_name = 'tenancy/tenant_list.html'


class TenantView(View):

    def get(self, request, slug):

        tenant = get_object_or_404(Tenant, slug=slug)
        stats = {
            'site_count': Site.objects.filter(tenant=tenant).count(),
            'rack_count': Rack.objects.filter(tenant=tenant).count(),
            'rackreservation_count': RackReservation.objects.filter(tenant=tenant).count(),
            'device_count': Device.objects.filter(tenant=tenant).count(),
            'vrf_count': VRF.objects.filter(tenant=tenant).count(),
            'prefix_count': Prefix.objects.filter(
                Q(tenant=tenant) |
                Q(tenant__isnull=True, vrf__tenant=tenant)
            ).count(),
            'ipaddress_count': IPAddress.objects.filter(
                Q(tenant=tenant) |
                Q(tenant__isnull=True, vrf__tenant=tenant)
            ).count(),
            'vlan_count': VLAN.objects.filter(tenant=tenant).count(),
            'circuit_count': Circuit.objects.filter(tenant=tenant).count(),
            'virtualmachine_count': VirtualMachine.objects.filter(tenant=tenant).count(),
        }

        # Draw network topology by vlan.
        devices = tenant.devices.all()
        connections = InterfaceConnection.objects.filter(
            Q(interface_a__device__in=devices) |
            Q(interface_b__device__in=devices))
        topology = draw_level_1_interface_connections_cytoscape(connections)

        return render(request, 'tenancy/tenant.html', {
            'tenant': tenant,
            'stats': stats,
            "topology": topology
        })


class TenantCreateView(PermissionRequiredMixin, ObjectEditView):
    permission_required = 'tenancy.add_tenant'
    model = Tenant
    model_form = forms.TenantForm
    template_name = 'tenancy/tenant_edit.html'
    default_return_url = 'tenancy:tenant_list'


class TenantEditView(TenantCreateView):
    permission_required = 'tenancy.change_tenant'


class TenantDeleteView(PermissionRequiredMixin, ObjectDeleteView):
    permission_required = 'tenancy.delete_tenant'
    model = Tenant
    default_return_url = 'tenancy:tenant_list'


class TenantBulkImportView(PermissionRequiredMixin, BulkImportView):
    permission_required = 'tenancy.add_tenant'
    model_form = forms.TenantCSVForm
    table = tables.TenantTable
    default_return_url = 'tenancy:tenant_list'


class TenantBulkEditView(PermissionRequiredMixin, BulkEditView):
    permission_required = 'tenancy.change_tenant'
    cls = Tenant
    queryset = Tenant.objects.select_related('group')
    filter = filters.TenantFilter
    table = tables.TenantTable
    form = forms.TenantBulkEditForm
    default_return_url = 'tenancy:tenant_list'


class TenantBulkDeleteView(PermissionRequiredMixin, BulkDeleteView):
    permission_required = 'tenancy.delete_tenant'
    cls = Tenant
    queryset = Tenant.objects.select_related('group')
    filter = filters.TenantFilter
    table = tables.TenantTable
    default_return_url = 'tenancy:tenant_list'
