import requests,sys,os,uuid
import subprocess
from datetime import datetime,timedelta
from dateutil.relativedelta import relativedelta
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.compute import ComputeManagementClient
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.compute.models import VirtualMachineScaleSet
from azure.mgmt.compute.models import VirtualMachineScaleSetExtensionProfile
from azure.mgmt.compute.models import VirtualMachineScaleSetExtension
from azure.mgmt.compute.models import VirtualMachineScaleSetVMProfile
from azure.mgmt.compute.models import VirtualMachineScaleSetOSProfile
from azure.mgmt.compute.models import VirtualMachineScaleSetStorageProfile
from azure.mgmt.compute.models import ImageReference
from azure.mgmt.authorization.models import RoleAssignmentCreateParameters
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.models import AccountSasParameters
from azure.mgmt.web import WebSiteManagementClient
from build_user_data import get_user_data,fetch_keyvault_refrences,set_dt_secrets
from msrestazure.azure_exceptions import CloudError
import configparser
from azure.storage.common import (AccessPolicy, ResourceTypes, AccountPermissions, storageclient, Services, SharedAccessSignature)
#import urllib,base64,hmac,hashlib
from design_time_helpers import validate_dt_ep
root_dir = os.path.dirname(os.path.realpath(__file__))


subscriptionId = os.getenv('AZURE_SUBSCRIPTION_ID')
def get_credential():
    try:
        credentials = ServicePrincipalCredentials(
            client_id = os.getenv('AZURE_CLIENT_ID'),
            secret = os.getenv('AZURE_CLIENT_SECRET'),
            tenant = os.getenv('AZURE_TENANT_ID'))
        return credentials
    except TypeError:
        print('\nERROR: Kindly Export the below Environmental vairables to continue ..')
        print('\nAZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID & AZURE_SUBSCRIPTION_ID')
        sys.exit(1)
    

credentials = get_credential()

compute_client = ComputeManagementClient(credentials,subscriptionId)
network_client = NetworkManagementClient(credentials,subscriptionId)
storage_client = StorageManagementClient(credentials,subscriptionId)
resource_client = ResourceManagementClient(credentials, subscriptionId)
auth_client = AuthorizationManagementClient(credentials, subscriptionId)
kv_client = KeyVaultManagementClient(credentials,subscriptionId)
funcapp_client = WebSiteManagementClient(credentials,subscriptionId)


def banner():
    size = int(os.popen('tput cols').read().strip())
    print('\n')
    print('#' * size)
    #print(comment.center(size))
    #print('#' * size,'\n')

def run_script(script_location):
    #args = shlex.split(command)
    output = subprocess.call([script_location])
    return output
        
def get_storage_account_keys(resource_group,storage_account):
    try:
        storage_acc_info=storage_client.storage_accounts.list_keys(resource_group,storage_account)
        for keys in storage_acc_info.keys:
            return keys.value
    except Exception as ex:
        print('Exception:')
        print(ex)
        sys.exit(1)

def get_sas_token(resourceGroupName,storageAccount):
    #expiry=datetime.utcnow() + relativedelta(years=10)
    account_key = get_storage_account_keys(resourceGroupName,storageAccount)
    sas_service_client = SharedAccessSignature(storageAccount, 
        account_key, 
        x_ms_version='2018-03-28')
    protocol = "https"
    resource_types = ResourceTypes(service=True, container=True, object=True)
    account_permissions = AccountPermissions(read=True, write=True, delete=True, list=True,add=True, create=True, update=True, process=True, _str=None)
    expiry = datetime.utcnow() + timedelta(weeks=520)
    start = None
    ip = None
    services = Services(blob=True, queue=True, file=True, table=True, _str=None)
    sas_token = sas_service_client.generate_account(services, resource_types, account_permissions, expiry, start, ip, protocol)
    return sas_token

# def get_sas_token(resourceGroupName,storage_account):
#     st= str((datetime.utcnow() - timedelta(minutes=5) ).strftime("%Y-%m-%dT%H:%M:%SZ"))
#     se= str((datetime.utcnow() + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))
#     storage_key = get_storage_account_keys(resourceGroupName,storage_account)
#     inputvalue = "{0}\n{1}\n{2}\n{3}\n{4}\n{5}\n{6}\n{7}\n{8}\n".format(
#         storage_account,  # 0. account name
#         'rwdlacup',                   # 1. signed permission (sp)
#         'bqft',                  # 2. signed service (ss)
#         'sco',                  # 3. signed resource type (srt)
#         st,                   # 4. signed start time (st)
#         se,                   # 5. signed expire time (se)
#         '',                   # 6. signed ip
#         'https',              # 7. signed protocol
#         '2018-03-28').encode('utf-8')  # 8. signed version
#     # Create base64 encoded signature
#     hash =hmac.new(base64.b64decode(storage_key),inputvalue,hashlib.sha256).digest()
#     sig = base64.b64encode(hash)
#     querystring = {
#         'sv':  '2018-03-28',
#         'ss':  'bqft',
#         'srt': 'sco',
#         'sp': 'rwdlacup',
#         'se': se,
#         'st': st,
#         'spr': 'https',
#         'sig': sig,
#     }
#     sastoken = urllib.parse.urlencode(querystring)
#     return sastoken

def get_storage_account_info(resourceGroupName,storageAccount):
    storageData = storage_client.storage_accounts.get_properties(
        resource_group_name=resourceGroupName,
        account_name=storageAccount
    )
    storageAccount = storageData.id
    return storageAccount


def get_vmss_ip_list(vmScaleSetName,resourceGroupName):
    ip_list = []
    vmScaleSetVMList = compute_client.virtual_machine_scale_set_vms.list(resourceGroupName,vmScaleSetName)
    for each_vm in vmScaleSetVMList:
        nic_name = each_vm.network_profile_configuration.network_interface_configurations[0].name
        ip_config = each_vm.network_profile_configuration.network_interface_configurations[0].ip_configurations[0].name
        instance_id = each_vm.instance_id
        ip_address = network_client.network_interfaces.get_virtual_machine_scale_set_ip_configuration(resourceGroupName,
                        vmScaleSetName,instance_id,nic_name,ip_config).private_ip_address
        ip_list.append(ip_address)
    return ip_list

def get_vmss_data(vmScaleSetName,resourceGroupName):
    vmScaleSetData = compute_client.virtual_machine_scale_sets.get(resource_group_name=resourceGroupName,
                        vm_scale_set_name=vmScaleSetName)
    return vmScaleSetData

def update_vmss_image(vmScaleSetName,resourceGroupName,location,image_id):
    image_reference = ImageReference(id=image_id)
    storage_profile = VirtualMachineScaleSetStorageProfile(image_reference=image_reference)
    virtual_machine_profile = VirtualMachineScaleSetVMProfile(storage_profile=storage_profile)
    parameters = VirtualMachineScaleSet(location=location,virtual_machine_profile=virtual_machine_profile)
    vmScaleSetData = compute_client.virtual_machine_scale_sets.create_or_update(resource_group_name=resourceGroupName,
                        vm_scale_set_name=vmScaleSetName,parameters=parameters)

def update_vmss_custom_data(vmScaleSetName,resourceGroupName,location,custom_data):
    os_profile = VirtualMachineScaleSetOSProfile(custom_data=custom_data)
    virtual_machine_profile = VirtualMachineScaleSetVMProfile(os_profile=os_profile)
    parameters = VirtualMachineScaleSet(location=location,virtual_machine_profile=virtual_machine_profile)
    vmScaleSetData = compute_client.virtual_machine_scale_sets.create_or_update(resource_group_name=resourceGroupName,
                        vm_scale_set_name=vmScaleSetName,parameters=parameters)


def update_vmss(vmScaleSetName,resourceGroupName,location,custom_data,image_id):
    ########
    vmss_data = compute_client.virtual_machine_scale_sets.get(resourceGroupName,vmScaleSetName)
    StorageAccount = vmss_data.virtual_machine_profile.extension_profile.extensions[0].settings['StorageAccount']
    sas_token = get_sas_token(resourceGroupName,StorageAccount)
    protected_settings = {
        'storageAccountName': StorageAccount,
        'storageAccountSasToken': sas_token
    }
    print('SAS Token ====> {}'.format(sas_token))
    extension_profile=VirtualMachineScaleSetExtensionProfile(
        extensions=[
            VirtualMachineScaleSetExtension(
                name=vmss_data.virtual_machine_profile.extension_profile.extensions[0].name,
                protected_settings=protected_settings,
                
            )]
    )
    ########
    os_profile = VirtualMachineScaleSetOSProfile(
        custom_data=custom_data)
    image_reference = ImageReference(id=image_id)
    storage_profile = VirtualMachineScaleSetStorageProfile(image_reference=image_reference)
    virtual_machine_profile = VirtualMachineScaleSetVMProfile(
        os_profile=os_profile,
        storage_profile=storage_profile,
        extension_profile=extension_profile
    )
    update_parameters = VirtualMachineScaleSet(
        location=location,
        virtual_machine_profile=virtual_machine_profile
    )
    vmss = compute_client.virtual_machine_scale_sets.create_or_update(
        resource_group_name=resourceGroupName,
        vm_scale_set_name=vmScaleSetName,
        parameters=update_parameters
        )
    vmss.wait()
    vmss_data = vmss.result()
    vmss_id = vmss_data.id
    return vmss_id


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
    try:
        role_definition_id = get_role_definition(scope,role_name)
        parameters = RoleAssignmentCreateParameters(role_definition_id=role_definition_id,principal_id=principal_id)
        auth_client.role_assignments.create(scope,str(uuid.uuid4()),parameters=parameters)
    except CloudError as e:
        if 'already exists' in e.message:
            pass
        else:
            print('error : {}'.format(e.error))
            sys.exit()


def get_public_ip_address(resource_group,public_ip):
    pip = network_client.public_ip_addresses.get(resource_group,public_ip)
    return pip.ip_address

def get_key_vault_uri(resource_group,key_vault):
    kv = kv_client.vaults.get(resource_group,key_vault)
    return kv.properties.vault_uri

def validate_resource_by_id(id,api_version):
    #api_version='2016-08-30'
    try:
        resource_client.resources.get_by_id(id,api_version)
        return True
    except CloudError:
        return False


def get_resource_group_details(resource_group):
    data = {}
    try:
        rg = resource_client.resource_groups.get(resource_group)
    except CloudError:
        return None
    rg_id = rg.id
    data['resource_group'] = {'id':rg_id }

    #credential = DefaultAzureCredential()
    #compute = ComputeManagementClient(credentials,subscriptionId)
    #network = NetworkManagementClient(credentials,subscriptionId)
    keyvault_gen = resource_client.resources.list_by_resource_group(resource_group,filter='resourceType eq \'Microsoft.KeyVault/vaults\'')
    keyvault = extract_from_resource_generator(keyvault_gen)
    #print('Keyvault ===> {}\n'.format(keyvault))

    data['keyvault'] = keyvault[0]
    funcapp_gen = resource_client.resources.list_by_resource_group(resource_group,filter='resourceType eq \'Microsoft.Web/sites\'')
    funcapp = extract_from_resource_generator(funcapp_gen)
    #print('Function App ===> {}\n'.format(funcapp))

    data['function_app'] = funcapp[0]
    #scaleset_gen = resource_client.resources.list_by_resource_group(resource_group,filter='resourceType eq \'Microsoft.Compute/virtualMachineScaleSets\' and tagName eq \'Subtype\' and tagValue eq \'message-processor\'')
    #scaleset_gen = resource_client.resources.list_by_resource_group(resource_group,filter='tagName eq \'Subtype\' and tagValue eq \'message-processor\'')
    scaleset_gen = resource_client.resources.list_by_resource_group(resource_group,filter='resourceType eq \'Microsoft.Compute/virtualMachineScaleSets\'')
    scaleset = extract_from_resource_generator(scaleset_gen)
    scaleset = [i for i in scaleset if i['tags']['Subtype'] == 'message-processor']
    #print('Scale Sets ===> {}\n'.format(scaleset))
    data['vmss'] = scaleset[0]

    public_ip_gen = resource_client.resources.list_by_resource_group(resource_group,filter='resourceType eq \'Microsoft.Network/publicIPAddresses\'')
    public_ip = extract_from_resource_generator(public_ip_gen)
    app_gw_public_ip = [i for i in public_ip if 'app-gw-pip' in i['name']]
    #print('Public IP ===> {}\n'.format(app_gw_public_ip))
    data['public_ip'] = app_gw_public_ip[0]

    storage_gen = resource_client.resources.list_by_resource_group(resource_group,filter='resourceType eq \'Microsoft.Storage/storageAccounts\'')
    storage = extract_from_resource_generator(storage_gen)
    storage = [i for i in storage if i['tags']['Subtype'] == 'backup']
    #print('Scale Sets ===> {}\n'.format(scaleset))
    data['storage_accounts'] = storage[0]
    
    return data

def merge_dict(dict1, dict2):
    dict2.update(dict1)
    return(dict2)
    
def update_function_app_propeties(resourceGroupName,functionApp,data):
    app_settings = funcapp_client.web_apps.list_application_settings(
        resource_group_name=resourceGroupName,
        name=functionApp)
    existing_properties = app_settings.properties
    #existing_properties = merge_dict(existing_properties,data)
    for i in data:
        existing_properties[i] = data[i]
    app_settings_update = funcapp_client.web_apps.update_application_settings(
        resource_group_name=resourceGroupName,
        name=functionApp, 
        properties=existing_properties)


def main():
    config = configparser.ConfigParser(allow_no_value=False)
    config.optionxform=str
    config.read('input.properties')
    print('\nPopulating Inputs from "input.propeties" ...\n')

    ############### Populating Inputs ###############

    Project = config.get('RunTime','Project')
    ProxyCountThreshold = config.get('RunTime','ProxyCountThreshold')
    ImageID = config.get('RunTime','ImageID')

    dt_oauth_host = config.get('DesignTime','dt_oauth_host')
    dt_oauth_username = config.get('DesignTime','dt_oauth_username')
    dt_oauth_password = config.get('DesignTime','dt_oauth_password')
    dt_apiportal_host = config.get('DesignTime','dt_apiportal_host')

    ############### Populating Inputs ###############

    ImageIdResourceGroup = '/'.join(ImageID.split('/')[:5])
    resource_group = Project + '-rg'
    print('\nPopulating Resources from  Resource Group - {}\n'.format(resource_group))
    data = get_resource_group_details(resource_group)
    if data is None:
        print('Resource Group - {} Not found'.format(resource_group))
        sys.exit(0)
    print('Validating ImageID ...\n')
    if validate_resource_by_id(ImageID,'2016-08-30'):
        print('ImageID is Valid\n'.format(ImageID))
        pass
    else:
        print('Not a Valid ImageID - {}'.format(ImageID))
        sys.exit(0)
    print('Validating Design Time Inputs ...')
    if validate_dt_ep(dt_oauth_host,dt_apiportal_host,dt_oauth_username,dt_oauth_password):
        print('Design Time Inputs are Valid\n'.format(ImageID))
    else:
        print('Design Time Inputs are NOT Valid\n'.format(ImageID))
        sys.exit(0)
    ms_ip = get_public_ip_address(resource_group,data['public_ip']['name'])
    vault_uri = get_key_vault_uri(resource_group,data['keyvault']['name'])
    storage_account = data['storage_accounts']['name']
    mp_vmss = data['vmss']['name']
    function_app = data['function_app']['name']
    print('Scanned Resource Info: ')
    banner()
    print('MP Scale Set : {}'.format(mp_vmss))
    print('Function App : {}'.format(function_app))
    print('Vault URI : {}'.format(vault_uri))
    print('Storage Acount : {}'.format(storage_account))
    print('App Gateway Public IP : {}'.format(ms_ip))
    #print('User Data Base64 Encoded : {}\n'.format(user_data))
    user_data = get_user_data(ms_ip,vault_uri,storage_account)
    banner()
    print('Assiging Resource Group Owner role to  Function App : {}'.format(function_app))
    assign_role(data['resource_group']['id'],'Owner',data['function_app']['principal_id'])
    print('Finished Assiging roles to  Function App : {}'.format(function_app))

    print('Assiging Image Resource Read role to  Function App : {}'.format(function_app))
    assign_role(ImageIdResourceGroup,'Reader',data['function_app']['principal_id'])
    print('Finished Assiging roles to  Function App : {}'.format(function_app))
    banner()
    ###### Azure Vault Set Secrets ######
    print('Setting Azure Vault Secrets : {}'.format(vault_uri))
    set_dt_secrets(vault_uri,'dtoauthhost',dt_oauth_host)
    set_dt_secrets(vault_uri,'dtoauthusername',dt_oauth_username)
    set_dt_secrets(vault_uri,'dtoauthpassword',dt_oauth_password)
    set_dt_secrets(vault_uri,'dtapiportalhost',dt_apiportal_host)
    print('Finished Setting Azure Vault Secrets : {}'.format(vault_uri))
    ###### Azure Vault Set Secrets ######
    banner()
    ###### Function App Update Property ######
    vault_data = fetch_keyvault_refrences(vault_uri)
    vault_data['ProxyCountThreshold'] = ProxyCountThreshold
    print('Updating Function App properties : {}'.format(function_app))
    update_function_app_propeties(resource_group,function_app,vault_data)
    print('Finished Updating Function App properties : {}'.format(function_app))
    banner()
    ###### Function App Update Property ######
    vmss_data = get_vmss_data(mp_vmss,resource_group)
    print('Modifying Coustom Data & Image of  MP Scale Set  : {}'.format(mp_vmss))
    update_vmss(mp_vmss,resource_group,vmss_data.location,user_data,ImageID)
    print('Successfully Updated MP Scale Set  : {}'.format(mp_vmss))
    banner()
    ###### Function App Update ######
    print('Updating Function App Code : {}'.format(function_app))
    os.environ['root_dir'] = root_dir
    os.environ['func_app_name'] = function_app
    run_script('{}/publish_function_app.sh'.format(root_dir))
    print('\nFinished Updating Function App Code : {}'.format(function_app))
    ###### Function App Update ######
    banner()

if __name__ == '__main__':
    main()