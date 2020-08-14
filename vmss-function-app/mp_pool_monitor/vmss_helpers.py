import requests,sys,os,uuid
from __app__.mp_pool_monitor.cred_wrapper import CredentialWrapper
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
from azure.mgmt.compute.models import ImageReference
from azure.mgmt.authorization.models import RoleAssignmentCreateParameters
from azure.mgmt.keyvault import KeyVaultManagementClient

subscriptionId = os.getenv('WEBSITE_OWNER_NAME').split('+')[0]
credentials = CredentialWrapper()

computeclient = ComputeManagementClient(credentials,subscriptionId)
networkClient = NetworkManagementClient(credentials,subscriptionId)
auth_client = AuthorizationManagementClient(credentials, subscriptionId)
kv_client = KeyVaultManagementClient(credentials,subscriptionId)
resource_client = ResourceManagementClient(credentials, subscriptionId)

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