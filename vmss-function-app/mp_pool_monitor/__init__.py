import datetime
import logging
from __app__.mp_pool_monitor.vmss_helpers import get_mp_scale_sets,get_vmss_ip_list,clone_vmss
from __app__.mp_pool_monitor.apigee_util_methods import get_uuid_from_ip,get_mp_proxy_count
import os
import azure.functions as func

def check_vmss(vmss_uuid_map,ProxyCountThreshold):
    createVMssFlag = True
    VmssProxyCount = None
    active_vmss = list(vmss_uuid_map.keys())[0]
    for each_vmss in vmss_uuid_map:
        if vmss_uuid_map[each_vmss]['proxy_count'] >= ProxyCountThreshold:
            createVMssFlag = createVMssFlag and True
            if VmssProxyCount is not None:
                if VmssProxyCount < vmss_uuid_map[each_vmss]['proxy_count']:
                    pass
                else:
                    active_vmss = each_vmss
                    VmssProxyCount = vmss_uuid_map[each_vmss]['proxy_count']
            else:
                VmssProxyCount = vmss_uuid_map[each_vmss]['proxy_count']
                active_vmss = each_vmss
        else:
            createVMssFlag = createVMssFlag and False
            if VmssProxyCount is not None:
                if VmssProxyCount < vmss_uuid_map[each_vmss]['proxy_count']:
                    pass
                else:
                    active_vmss = each_vmss
                    VmssProxyCount = vmss_uuid_map[each_vmss]['proxy_count']
            else:
                VmssProxyCount = vmss_uuid_map[each_vmss]['proxy_count']
                active_vmss = each_vmss
    return createVMssFlag,active_vmss


def main(mytimer: func.TimerRequest) -> None:
    ProxyCountThreshold = int(os.getenv("ProxyCountThreshold"))
    protocol = os.getenv("protocol")
    port = os.getenv("port")
    ms_ip = os.getenv("ms_ip")
    username = os.getenv("user_name")
    password = os.getenv("password")
    region = os.getenv("region")
    baseUrl = protocol+ '://' + ms_ip + ':' + port
    pod = os.getenv("pod")
    compType = 'message-processor'
    component_name = 'mp'
    logging.info("Component Name {}" .format(compType))
    utc_timestamp = datetime.datetime.utcnow().replace(
        tzinfo=datetime.timezone.utc).isoformat()
    #logging.info('env variables {}'.format(os.environ))
    function_app = os.getenv('WEBSITE_SITE_NAME')
    resource_group = '-'.join(function_app.split('-')[:-1]) + '-rg'
    subscriptionId = os.getenv('WEBSITE_OWNER_NAME').split('+')[0]
    mp_scale_sets = get_mp_scale_sets(resource_group)
    index = 0
    for each_vmss in mp_scale_sets['vmss']:
        ip_list = get_vmss_ip_list(each_vmss['name'],resource_group)
        uuid_list = []
        for each_ip in ip_list:
            uuid = get_uuid_from_ip(baseUrl,username,password,pod,compType,region,each_ip)
            if uuid is not None:
                uuid_list.append(uuid)
        if len(uuid_list) > 0:
            proxy_count = get_mp_proxy_count(baseUrl,username,password,uuid_list[0])
            mp_scale_sets['vmss'][index]['uuid_list'] = uuid_list
            mp_scale_sets['vmss'][index]['ip_list'] = ip_list
            mp_scale_sets['vmss'][index]['proxy_count'] = proxy_count
            index += 1
        else:
            mp_scale_sets['vmss'][index]['proxy_count'] = 0
    vmss_uuid_map ={ i['name']: {'proxy_count': i['proxy_count']} for i in mp_scale_sets['vmss']}
    createVMssFlag,active_vmss = check_vmss(vmss_uuid_map,ProxyCountThreshold)
    logging.info('mp_scale_sets {}'.format(mp_scale_sets))
    logging.info('active_vmss =====> {}'.format(active_vmss))
    logging.info('createVMssFlag =====> {}'.format(createVMssFlag))
    count = len(mp_scale_sets['vmss'])
    if createVMssFlag:
        logging.info('Creating new VM Scale se')
        clone_vmss(active_vmss,resource_group,count)
    logging.info('Python timer trigger function ran at %s', utc_timestamp)