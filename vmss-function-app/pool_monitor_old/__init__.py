import logging
import os,sys
import azure.functions as func
"""
#from azure.identity import DefaultAzureCredential
from __app__.pool_monitor.cred_wrapper import CredentialWrapper
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.storage.queue import QueueClient

#credential = DefaultAzureCredential()
credential = CredentialWrapper()


subscription_id = os.getenv('ARM_SUBSCRIPTION_ID')
resource_group = os.getenv('resource_group')
vmss_name = os.getenv('vmss_name')
storage_account = os.getenv('storage_account')
queue_name = os.getenv('queue_name')


def get_storage_account_keys(credentials,resource_group,storage_account):
    try:
        storageClient=StorageManagementClient(credentials,subscription_id)
        storage_acc_info=storageClient.storage_accounts.list_keys(resource_group,storage_account)
        for keys in storage_acc_info.keys:
            return keys.value
    except Exception as ex:
        logging.error('Exception: {}'.format(ex))
        sys.exit(1)
"""
"""
def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    
    response_data = req.get_json()
    logging.info('response_data ==> {}'.format(response_data))
    if response_data['data']['status'] == 'Activated':
        logging.info('VMSS =={}'.format(vmss_name))
        #compute = ComputeManagementClient(credential,subscription_id)
        #instance_ids = [ i.instance_id for i in compute.virtual_machine_scale_set_vms.list(resource_group,vmss_name)]
        logging.info('storage_account ==> {}'.format(storage_account))
        logging.info('Storage queue_name ==> {}'.format(queue_name))
        storageAccessKey =  get_storage_account_keys(credential,resource_group,storage_account)
        storageConnectionString = 'DefaultEndpointsProtocol=https;AccountName={};AccountKey={};EndpointSuffix=core.windows.net'.format(storage_account,storageAccessKey)
        queue_client = QueueClient.from_connection_string(storageConnectionString, queue_name)
        logging.info('Sending Message to Queue ==> {}'.format(queue_name))
        queue_client.send_message(u"Scale Out",time_to_live=120)
        return func.HttpResponse("Message Sent to Message Queue")
    else:
        logging.info('Alert Has been Resolved. No Action')
        return func.HttpResponse("Alert Has been Resolved. No Action")
"""

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    logging.info('{}'.format(os.environ))

    return func.HttpResponse("Response ==> {}".format(req.))