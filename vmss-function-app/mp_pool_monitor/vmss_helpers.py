import requests,sys,os,uuid
import logging
from datetime import datetime
from dateutil.relativedelta import relativedelta
from __app__.mp_pool_monitor.cred_wrapper import CredentialWrapper
from __app__.mp_pool_monitor.build_user_data import get_user_data
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.compute import ComputeManagementClient
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.compute.models import VirtualMachineScaleSet
from azure.mgmt.compute.models import VirtualMachineScaleSetVMProfile
from azure.mgmt.compute.models import VirtualMachineScaleSetOSProfile
from azure.mgmt.compute.models import VirtualMachineScaleSetStorageProfile
from azure.mgmt.compute.models import VirtualMachineScaleSetIdentity
from azure.mgmt.compute.models import ImageReference
from azure.mgmt.compute.models import Sku
from azure.mgmt.compute.models import VirtualMachineScaleSetExtensionProfile
from azure.mgmt.compute.models import VirtualMachineScaleSetExtension
from azure.mgmt.authorization.models import RoleAssignmentCreateParameters
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.models import AccountSasParameters
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.monitor.models import AutoscaleSettingResource
from azure.mgmt.monitor.models import AutoscaleProfile
from azure.mgmt.monitor.models import ScaleRule
from azure.mgmt.monitor.models import MetricTrigger
from azure.mgmt.monitor.models import ActivityLogAlertResource
from azure.mgmt.monitor.models import ActivityLogAlertAllOfCondition
from azure.mgmt.monitor.models import ActivityLogAlertLeafCondition

subscriptionId = os.getenv('WEBSITE_OWNER_NAME').split('+')[0]
credentials = CredentialWrapper()

computeclient = ComputeManagementClient(credentials,subscriptionId)
networkClient = NetworkManagementClient(credentials,subscriptionId)
auth_client = AuthorizationManagementClient(credentials, subscriptionId)
kv_client = KeyVaultManagementClient(credentials,subscriptionId)
resource_client = ResourceManagementClient(credentials, subscriptionId)
storage_client = StorageManagementClient(credentials,subscriptionId)
monitor_client = MonitorManagementClient(credentials,subscriptionId)


def get_sas_token(resourceGroupName,storageAccount):
    expiry=datetime.utcnow() + relativedelta(years=20)
    SasParameters = AccountSasParameters(
        services='bqft',
        resource_types='sco',
        permissions='rwdlacup',
        protocols='https',
        shared_access_expiry_time=expiry
    )
    SasData = storage_client.storage_accounts.list_account_sas(
        resource_group_name=resourceGroupName,
        account_name=storageAccount,
        parameters= SasParameters
    )
    sas_token = SasData.account_sas_token
    return sas_token

def get_storage_account_info(resourceGroupName,storageAccount):
    storageData = storage_client.storage_accounts.get_properties(
        resource_group_name=resourceGroupName,
        account_name=storageAccount
    )
    storageAccount = storageData.id
    return storageAccount

def clone_activity_log(resourceGroupName,VmScaleSetID):
    activity_log_alerts = monitor_client.activity_log_alerts.list_by_resource_group(resourceGroupName)
    existing_mp_activitylog_alerts = [i.name for i in activity_log_alerts if 'mp-alert' in i.name]
    count = len(existing_mp_activitylog_alerts) + 1
    existing_mp_activitylog_alert = existing_mp_activitylog_alerts[0]
    new_mp_activitylog_alert_name = existing_mp_activitylog_alert[:-1] + str(count)
    existing_alert = monitor_client.activity_log_alerts.get(resourceGroupName,existing_mp_activitylog_alert)
    condition = ActivityLogAlertAllOfCondition(
        all_of = [
            ActivityLogAlertLeafCondition(
                field = 'category',
                equals = 'Administrative'
            ),
            ActivityLogAlertLeafCondition(
                field = 'operationName',
                equals = 'Microsoft.Compute/virtualMachineScaleSets/delete/action'
            ),ActivityLogAlertLeafCondition(
                field = 'resourceId',
                equals = VmScaleSetID
            )
        ]
    )
    activity_log_alert = ActivityLogAlertResource(
            location=existing_alert.location,
            scopes=existing_alert.scopes,
            actions=existing_alert.actions,
            condition=condition
    )
    alert = monitor_client.activity_log_alerts.create_or_update(
        resource_group_name = resourceGroupName,
        activity_log_alert_name = new_mp_activitylog_alert_name,
        activity_log_alert = activity_log_alert
        )

def create_autoscaling_settings(ExistingVmScaleSetName,VmScaleSetID,resourceGroupName):
    NewVmScaleSetName = VmScaleSetID.split('/')[-1]
    existing_asg = monitor_client.autoscale_settings.get(
        resource_group_name=resourceGroupName,
        autoscale_setting_name=ExistingVmScaleSetName)    
    rules = [ ScaleRule(
                metric_trigger=MetricTrigger(
                    metric_name =i.metric_trigger.metric_name,
                    #metric_namespace=i.metric_trigger.additional_properties['metricNamespace'],
                    metric_resource_uri = VmScaleSetID,
                    time_grain = i.metric_trigger.time_grain,
                    statistic = i.metric_trigger.statistic,
                    time_window = i.metric_trigger.time_window,
                    time_aggregation = i.metric_trigger.time_aggregation,
                    operator = i.metric_trigger.operator,
                    threshold = i.metric_trigger.threshold
                    #dimensions = i.metric_trigger.additional_properties['dimensions'] 
                ),
                scale_action=i.scale_action) for i in existing_asg.profiles[0].rules  
        ]
    profile = AutoscaleProfile(
        name = existing_asg.profiles[0].name,
        capacity = existing_asg.profiles[0].capacity,
        rules = rules,
        fixed_date = None,
        recurrence = None
    )
    parameters = AutoscaleSettingResource(
        location = existing_asg.location ,
        tags = existing_asg.tags ,
        profiles = [profile],
        notifications = existing_asg.notifications,
        enabled = True,
        autoscale_setting_resource_name = NewVmScaleSetName,
        target_resource_uri = VmScaleSetID
    )
    new_asg = monitor_client.autoscale_settings.create_or_update(
        resource_group_name= resourceGroupName,
        autoscale_setting_name = NewVmScaleSetName,
        parameters = parameters
    )


def clone_vmss(vmScaleSetName,resourceGroupName,count):
    logging.info("Collectiong Data from VM Scale Set {}" .format(vmScaleSetName))
    vmss_data = computeclient.virtual_machine_scale_sets.get(resourceGroupName,vmScaleSetName)
    StorageAccount = vmss_data.virtual_machine_profile.extension_profile.extensions[0].settings['StorageAccount']
    logging.info("Fetching  Data from Storage Account {}" .format(StorageAccount))
    StorageAccountId = get_storage_account_info(resourceGroupName,StorageAccount)
    custom_data = get_user_data(StorageAccount)
    sku = Sku(
        name = vmss_data.sku.name,
        tier = vmss_data.sku.tier,
        capacity = 0
    )
    os_profile = VirtualMachineScaleSetOSProfile(
        computer_name_prefix=vmss_data.virtual_machine_profile.os_profile.computer_name_prefix + str(count + 1),
        admin_username=vmss_data.virtual_machine_profile.os_profile.admin_username,
        windows_configuration= None,
        linux_configuration=vmss_data.virtual_machine_profile.os_profile.linux_configuration,
        custom_data=custom_data)
    virtual_machine_profile = VirtualMachineScaleSetVMProfile(
        os_profile=os_profile,
        storage_profile=vmss_data.virtual_machine_profile.storage_profile,
        #additional_capabilities=vmss_data.virtual_machine_profile.additional_capabilities,
        network_profile=vmss_data.virtual_machine_profile.network_profile,
        diagnostics_profile=vmss_data.virtual_machine_profile.diagnostics_profile
    )
    new_vmss_parameters = VirtualMachineScaleSet(
        location=vmss_data.location,
        tags=vmss_data.tags,
        sku=sku,
        plan=vmss_data.plan,
        upgrade_policy=vmss_data.upgrade_policy,
        virtual_machine_profile=virtual_machine_profile,
        overprovision=vmss_data.overprovision,
        do_not_run_extensions_on_overprovisioned_vms=vmss_data.do_not_run_extensions_on_overprovisioned_vms,
        single_placement_group=vmss_data.single_placement_group,
        zone_balance=vmss_data.zone_balance,
        platform_fault_domain_count=vmss_data.platform_fault_domain_count,
        identity = VirtualMachineScaleSetIdentity(type='SystemAssigned'),
        zones=vmss_data.zones
    )
    new_vm_scale_set=vmScaleSetName[:-1] + str(count + 1)
    logging.info("Creating VM Scale Set with Name:  {}" .format(new_vm_scale_set))
    new_vmss = computeclient.virtual_machine_scale_sets.create_or_update(
        resource_group_name=resourceGroupName,
        vm_scale_set_name=new_vm_scale_set,
        parameters=new_vmss_parameters
        )
    new_vmss.wait()
    new_vmss_data = new_vmss.result()
    new_vmss_id = new_vmss_data.id
    new_vmss_principal_id = new_vmss_data.identity.principal_id
    logging.info("Assiging Role - {} on Scope - {} for Prinicpal - {}".format('Owner',new_vmss_id,new_vmss_principal_id))
    assign_role(new_vmss_id,'Owner',new_vmss_principal_id)
    logging.info("Assiging Role - {} on Scope - {} for Prinicpal - {}".format('Storage Blob Data Contributor',StorageAccountId,new_vmss_principal_id))
    assign_role(StorageAccountId,'Storage Blob Data Contributor',new_vmss_principal_id)

    extension_settings = vmss_data.virtual_machine_profile.extension_profile.extensions[0].settings
    extension_settings['ladCfg']['diagnosticMonitorConfiguration']['metrics']['resourceId'] = new_vmss_id
    sas_token = get_sas_token(resourceGroupName,StorageAccount)
    protected_settings = {
        'storageAccountName': StorageAccount,
        'storageAccountSasToken': sas_token
    }

    extension_profile=VirtualMachineScaleSetExtensionProfile(
        extensions=[
            VirtualMachineScaleSetExtension(
                name=vmss_data.virtual_machine_profile.extension_profile.extensions[0].name,
                force_update_tag=vmss_data.virtual_machine_profile.extension_profile.extensions[0].force_update_tag,
                publisher=vmss_data.virtual_machine_profile.extension_profile.extensions[0].publisher,
                #type1=vmss_data.virtual_machine_profile.extension_profile.extensions[0].type,
                type=vmss_data.virtual_machine_profile.extension_profile.extensions[0].type,
                type_handler_version=vmss_data.virtual_machine_profile.extension_profile.extensions[0].type_handler_version,
                auto_upgrade_minor_version=vmss_data.virtual_machine_profile.extension_profile.extensions[0].auto_upgrade_minor_version,
                settings=extension_settings,
                protected_settings=protected_settings,
                provision_after_extensions=vmss_data.virtual_machine_profile.extension_profile.extensions[0].provision_after_extensions
            )]
    )
    update_virtual_machine_profile = VirtualMachineScaleSetVMProfile(extension_profile=extension_profile)
    update_parameters = VirtualMachineScaleSet(
        location=vmss_data.location,
        virtual_machine_profile=update_virtual_machine_profile)
    logging.info("Setting Linux Diagnositc Extension on  VM Scale Set :  {}" .format(new_vm_scale_set))
    new_vmss_update = computeclient.virtual_machine_scale_sets.create_or_update(
        resource_group_name=resourceGroupName,
        vm_scale_set_name=new_vm_scale_set,
        parameters=update_parameters)
    new_vmss_update.wait()

    #############
    """
    updatedsku = Sku(
        name = vmss_data.sku.name,
        tier = vmss_data.sku.tier,
        capacity = 2
    )
    updated_vmss_parameters = VirtualMachineScaleSet(
        location=vmss_data.location,
        sku=updatedsku
    )
    new_vmss = computeclient.virtual_machine_scale_sets.create_or_update(
        resource_group_name=resourceGroupName,
        vm_scale_set_name=new_vm_scale_set,
        parameters=updated_vmss_parameters
        )
    new_vmss.wait()
    """
    #############
    logging.info("Creating AutoScale Setting for   VM Scale Set :  {}" .format(new_vm_scale_set))
    create_autoscaling_settings(vmScaleSetName,new_vmss_id,resourceGroupName)
    
    logging.info("Creating Activity Log Alert for VM Scale Set :  {}" .format(new_vm_scale_set))
    clone_activity_log(resourceGroupName,new_vmss_id)
    logging.info("Finished Creating Activity Log Alert for VM Scale Set :  {}" .format(new_vm_scale_set))

    logging.info("Successfully Cloned VM ScaleSet {} to create {}" .format(vmScaleSetName,new_vm_scale_set))


def get_vmss_ip_list(vmScaleSetName,resourceGroupName):
    ip_list = []
    vmScaleSetVMList = computeclient.virtual_machine_scale_set_vms.list(resourceGroupName,vmScaleSetName)
    for each_vm in vmScaleSetVMList:
        nic_name = each_vm.network_profile_configuration.network_interface_configurations[0].name
        ip_config = each_vm.network_profile_configuration.network_interface_configurations[0].ip_configurations[0].name
        instance_id = each_vm.instance_id
        ip_address = networkClient.network_interfaces.get_virtual_machine_scale_set_ip_configuration(resourceGroupName,
                        vmScaleSetName,instance_id,nic_name,ip_config).private_ip_address
        ip_list.append(ip_address)
    return ip_list

def get_vmss_data(vmScaleSetName,resourceGroupName):
    vmScaleSetData = computeclient.virtual_machine_scale_sets.get(resource_group_name=resourceGroupName,
                        vm_scale_set_name=vmScaleSetName)
    return vmScaleSetData

def update_vmss_image(vmScaleSetName,resourceGroupName,location,image_id):
    image_reference = ImageReference(id=image_id)
    storage_profile = VirtualMachineScaleSetStorageProfile(image_reference=image_reference)
    virtual_machine_profile = VirtualMachineScaleSetVMProfile(storage_profile=storage_profile)
    parameters = VirtualMachineScaleSet(location=location,virtual_machine_profile=virtual_machine_profile)
    vmScaleSetData = computeclient.virtual_machine_scale_sets.create_or_update(resource_group_name=resourceGroupName,
                        vm_scale_set_name=vmScaleSetName,parameters=parameters)

def update_vmss_custom_data(vmScaleSetName,resourceGroupName,location,custom_data):
    os_profile = VirtualMachineScaleSetOSProfile(custom_data=custom_data)
    virtual_machine_profile = VirtualMachineScaleSetVMProfile(os_profile=os_profile)
    parameters = VirtualMachineScaleSet(location=location,virtual_machine_profile=virtual_machine_profile)
    vmScaleSetData = computeclient.virtual_machine_scale_sets.create_or_update(resource_group_name=resourceGroupName,
                        vm_scale_set_name=vmScaleSetName,parameters=parameters)


def extract_from_resource_generator(gen):
    resources = []
    for i in gen:
        try:
            principal_id = i.identity.principal_id
        except AttributeError:
            principal_id = None
        resources.append({'name': i.name,'id': i.id,'principal_id': principal_id,'tags':i.tags })
    return resources

def get_role_definition(scope,role_name):
    role_definitions = auth_client.role_definitions.list(scope)
    return [ i.id for i in role_definitions if i.role_name == role_name][0]

def assign_role(scope,role_name,principal_id):
    role_definition_id = get_role_definition(scope,role_name)
    parameters = RoleAssignmentCreateParameters(role_definition_id=role_definition_id,principal_id=principal_id)
    auth_client.role_assignments.create(scope,str(uuid.uuid4()),parameters=parameters)

def get_public_ip_address(resource_group,public_ip):
    pip = networkClient.public_ip_addresses.get(resource_group,public_ip)
    return pip.ip_address

def get_key_vault_uri(resource_group,key_vault):
    kv = kv_client.vaults.get(resource_group,key_vault)
    return kv.properties.vault_uri

def get_mp_scale_sets(resource_group):
    data = {}
    scaleset_gen = resource_client.resources.list_by_resource_group(resource_group,filter='resourceType eq \'Microsoft.Compute/virtualMachineScaleSets\'')
    scaleset = extract_from_resource_generator(scaleset_gen)
    scaleset = [i for i in scaleset if i['tags']['Subtype'] == 'message-processor']
    data['vmss'] = scaleset
    return data