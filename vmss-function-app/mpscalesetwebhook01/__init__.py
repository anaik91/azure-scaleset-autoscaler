import logging
from __app__.scale_set_python import remove_uuid
from __app__.scale_set_python import apigee_util_methods as apigee_utils
from __app__.mpscalesetwebhook01.cred_wrapper import CredentialWrapper
import os
import time
import azure.functions as func
from azure.mgmt.compute import ComputeManagementClient
#from azure.mgmt.compute.v2020_06_01.models import VirtualMachineScaleSet
from azure.mgmt.compute.models import VirtualMachineScaleSet

def get_vmss_data(client,vmScaleSetName,resourceGroupName):
    vmScaleSetData = client.virtual_machine_scale_sets.get(resource_group_name=resourceGroupName,
                        vm_scale_set_name=vmScaleSetName)
    return vmScaleSetData

def create_vmss_tag(client,vmScaleSetName,resourceGroupName,location,tags):
    params = VirtualMachineScaleSet(location=location,tags=tags)
    vmScaleSetData = client.virtual_machine_scale_sets.create_or_update(resource_group_name=resourceGroupName,
                        vm_scale_set_name=vmScaleSetName,parameters=params)

def handle_dead_uuid(vmss_data,uuid):
    subscriptionId = vmss_data['context']['subscriptionId']
    resourceGroupName = vmss_data['context']['resourceGroupName']
    vmScaleSetName = vmss_data['context']['resourceName']
    location = vmss_data['context']['resourceRegion']
    credential = CredentialWrapper()
    compute = ComputeManagementClient(credential,subscriptionId)
    vmScaleSetData = get_vmss_data(compute,vmScaleSetName,resourceGroupName)
    vmScaleSetTags = vmScaleSetData.tags
    try:
        dead_uuid_list = vmScaleSetTags['dead_uuid_list']
        if vmss_data['disaster']:
            correlationId = vmss_data['data']['context']['activityLog']['correlationId']
            if uuid in vmScaleSetTags:
                if vmScaleSetTags[uuid] == correlationId:
                    logging.info('No need to update dead_uuid_list Tag,As this is a Re-Run for correlationId:{}'.format(correlationId))
                    return True
                else:
                    logging.info('Set Existing uuid to CorrelationID mapping ==> {}:{}'.format(uuid,correlationId))
                    vmScaleSetTags[uuid] = correlationId
            else:
                vmScaleSetTags[uuid] = correlationId
                logging.info('Set uuid to CorrelationID mapping for First Time==> {}:{}'.format(uuid,correlationId))
        #else:
        if len(dead_uuid_list) > 0:
            dead_uuid_list = dead_uuid_list.split(',')
            dead_uuid_list.append(uuid)
            updated_dead_uuid_list = ','.join(set(dead_uuid_list))
            vmScaleSetTags['dead_uuid_list'] = updated_dead_uuid_list
        else:
            vmScaleSetTags['dead_uuid_list'] = uuid
    except KeyError:
        vmScaleSetTags['dead_uuid_list'] = uuid
    logging.info('Updating Scale Set : {} with tag dead_uuid_list with value {}'.format(vmScaleSetName,vmScaleSetTags['dead_uuid_list']))
    create_vmss_tag(compute,vmScaleSetName,resourceGroupName,location,vmScaleSetTags)

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    logging.info ("Scale Operation : {}".format(req.get_json()))
    logging.info("Component type received {}".format(req.params.get("compType")))
    scale_operation = req.get_json()
    scale_operation['disaster'] = False
    if 'schemaId' in scale_operation:
        if 'Microsoft.Insights/activityLogs' in scale_operation['schemaId']:
            scale_operation['operation'] = 'Scale In'
            scale_operation['disaster'] = True
            scale_operation['context'] = {
                'subscriptionId': scale_operation['data']['context']['activityLog']['subscriptionId'],
                'resourceGroupName': scale_operation['data']['context']['activityLog']['resourceGroupName'],
                'resourceName': scale_operation['data']['context']['activityLog']['resourceId'].split('/')[-1],
                'resourceRegion': os.getenv("Location")
            }
        else:
            pass
    else:
        pass
    logging.info("Scale Operation {}".format(scale_operation['operation']))
    protocol = os.getenv("protocol")
    port = os.getenv("port")
    ms_ip = os.getenv("ms_ip")
    username = os.getenv("user_name")
    password = os.getenv("password")
    region = os.getenv("region")
    baseUrl = protocol+ '://' + ms_ip + ':' + port
    pod = os.getenv("pod")
    stale_retry = int(os.getenv("stale_retry"))
    compType = req.params.get("compType")
    component_name = req.params.get("component_name")
    logging.info("Component Name {}" .format(compType))
    while (stale_retry >= 0):
        if (scale_operation['operation'] == "Scale In"):
            logging.info("Inside Scale in condition")
            time.sleep(5)
            logging.info("Stale entry deletion retry count {}".format(stale_retry))
            logging.info("sleep complete for 5 seconds")
            dead_mp_uuid = apigee_utils.list_dead_mp(baseUrl,username,password,pod,compType,region)
            logging.info("Dead Router/MP list {}".format(dead_mp_uuid))
            if len(dead_mp_uuid)!=0:
                for uuid in dead_mp_uuid:
                    logging.info("Dead Router/MP UUID {}".format(uuid))
                    if compType == 'message-processor':
                        handle_dead_uuid(scale_operation,uuid)
                    else:
                        remove_uuid.main(baseUrl,protocol,port,ms_ip,username,password,pod,compType,region,uuid,component_name)
            stale_retry-=1
            continue
        else: 
            logging.info(" Scale out opertation- Nothing to do")
            break
    return func.HttpResponse("Function Executed")