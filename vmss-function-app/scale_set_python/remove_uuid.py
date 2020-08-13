import re
import requests
import argparse
import logging
import os
import json
from requests.auth import HTTPBasicAuth
from __app__.scale_set_python import apigee_util_methods as apigee_utils
import threading

def main(baseUrl,protocol,port,ms_ip,username,password,pod,compType,region,uuid_input,component_name):
    logging.info("Main method started")
    uuid=""
    divide_count_stop = -1
    divide_count_start = 0
    threads = []
    logging.info(baseUrl)
    try:
        status, message = apigee_utils.checkMsStatus(baseUrl)
        print (status)
        logging.info("HTTP Response from MS server {}".format(status))
        if (status == 200):
            if (component_name == "r" and uuid_input is not None):
                compType = "router"
                uuid = uuid_input
                logging.info("Router UUID found {}".format(uuid))
                http_status, htttp_message = apigee_utils.remove_server_uuid(uuid,baseUrl,username,password,pod,compType,region)
                logging.info("Remove server from pods result {} {}".format(http_status,htttp_message))
                if http_status == 200:
                    status = apigee_utils.delete_server(baseUrl,uuid,username,password)
                else:
                    logging.error("Remove server from pods failed - {} {}".format(http_status,htttp_message))
                if status == 200:
                    logging.info("UUID Deleted from the server list {}".format(uuid))
                else:
                    logging.error("Delete server from server list failed - {}".format(status))
            if (component_name == "mp" and uuid_input is None):
                compType = "message-processor"
                orgs_list = apigee_utils.get_org_list(region,pod,baseUrl,username,password)
                org_len = len(orgs_list)
                print ("divide_count_stop {}".format(divide_count_stop))
                print ("org_len {}".format(org_len))
                for i in range(0,len(orgs_list),5):
                    divide_count_start=i     # 01,11,21,31,41
                    divide_count_stop=i+5     # 10,20,30,40,50
                    print ("Start_count & End_count {} {}".format(divide_count_start,divide_count_stop))
                    print ("ORGs in index {}".format(orgs_list[divide_count_start:divide_count_stop]))
                    logging.info("Start_count & End_count {} {}".format(divide_count_start,divide_count_stop))
                    logging.info("ORGs in index {}".format(orgs_list[divide_count_start:divide_count_stop]))
                    t1 = threading.Thread(target=apigee_utils.thread_handler_disassociate, args=(baseUrl,uuid,username,password,region,pod,divide_count_start,divide_count_stop,))
                    threads.append(t1)
                    for x in threads:
                        x.start()
                    for x in threads:
                        x.join()
                    logging.info("thread executed")
                    http_status, htttp_message = apigee_utils.remove_server_uuid(uuid,baseUrl,username,password,pod,compType,region)
                    print ("Remove server from pods result {}".format(http_status))
                    logging.info("Remove server from pods result {} {}".format(http_status,htttp_message))
                    if http_status == 200:
                        status = apigee_utils.delete_server(baseUrl,uuid,username,password)
                    else:
                        logging.error("Remove server from pods failed - {} {}".format(http_status,htttp_message))
                    if status == 200:
                        logging.info("UUID Deleted from the server list {}".format(uuid))
                    else:
                        logging.error("Delete server from server list failed - {}".format(status))
            if (component_name == "mp" and uuid_input is not None):
                print("UUID of Dead MP {}".format(uuid_input))
                logging.info("uuid------> of dead MP {} ".format(uuid_input))
                compType = "message-processor"
                orgs_list = apigee_utils.get_org_list(region,pod,baseUrl,username,password)
                org_len = len(orgs_list)
                for i in range(0,len(orgs_list),5):
                    divide_count_start=i     # 01,11,21,31,41
                    divide_count_stop=i+5     # 10,20,30,40,50           
                    logging.info("Start_count & End_count {} {}".format(divide_count_start,divide_count_stop))
                    logging.info("ORGs in index {}".format(orgs_list[divide_count_start:divide_count_stop]))
                    t1 = threading.Thread(target=apigee_utils.thread_handler_disassociate, args=(baseUrl,uuid_input,username,password,region,pod,divide_count_start,divide_count_stop,))
                    threads.append(t1)
                for x in threads:
                    x.start()
                for y in threads:
                    y.join()
                logging.info("Dissassociation Complete- Thread executed")
                http_status, htttp_message = apigee_utils.remove_server_uuid(uuid_input,baseUrl,username,password,pod,compType,region)
                logging.info("Remove server from pods result {} {}".format(http_status,htttp_message))
                if http_status == 200:
                    status = apigee_utils.delete_server(baseUrl,uuid_input,username,password)
                else:
                    logging.error("Remove server from pods failed - {} {}".format(http_status,htttp_message))
                if status == 200:
                    logging.info("UUID Deleted from the server list {}".format(uuid_input))
                else:
                    logging.error("Delete server from server list failed - {}".format(status))
        else:
          logging.error("Response from Management server {}".format(message))
    except Exception as err:
        logging.error(err)
        logging.error("Router/MP may be down")
