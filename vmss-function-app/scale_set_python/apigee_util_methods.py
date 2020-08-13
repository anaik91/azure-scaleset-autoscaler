import requests
import configparser
from requests.auth import HTTPBasicAuth
import warnings
import traceback
import logging
import json

def getMsCredentials(ms_cred_properties):
  username = None
  password = None
  try:
    with open (ms_cred_properties) as data:
      for i in data.readlines():
        if "ADMIN_EMAIL=" in i:
          username = i.split("=")[1].strip()
        elif "APIGEE_ADMINPW=" in i:
          password = i.split("=")[1].strip()
        else:
          if username is not None and password is not None:
            break
  except Exception as ex:
    logging.error(ex) 
    exit(2)
  #print ("Username: {} Password: {}".format(username,password))
  return username,password

def checkMsStatus(baseUrl):
  #print ("checkMsStatus")
  logging.info("############ Check MS Status Method  ###################")
  res = requests.get(baseUrl+"/v1/servers/self/up",verify=False)
  return res.status_code,res.text

def getIPs(baseUrl,username,password,pod,compType):
  logging.info("Get Details of {}".format(compType))
  res = requests.get(baseUrl+"/v1/servers?pod="+pod+"&"+"type="+compType, auth=(username,password),verify=False)
  return res

def packIPs(servers_json,ip_count):
  ip_mapping = []
#  count = ip_count
  for i in servers_json:
    ip_mapping.append("IP"+str(ip_count)+"="+str(i['internalIP']))
    ip_count = ip_count +1
  return ip_mapping,ip_count

def write_source_file(filename,data):
  with open(filename, "w+") as fp:
    for d in data:
      fp.write(d+"\n")

def append_source_file(filename,data):
  with open(filename, "a+") as fp:
    for d in data:
      fp.write(d+"\n")
def copyTemplate(source,destination):
  print ("copyTemplate")
  with open(source) as f:
    with open(destination, "a+") as f1:
      for line in f:
        print (line)
        f1.write(line)
def append_credentails(filename,data):
  with open(filename, "a+") as fp:
    for d in data:
      fp.write(d)
    fp.write("\n")

def checkServiceStatus(baseUrl):
  #print ("checkStatus")
  #log_file = os.path.join(os.path.dirname(os.path.realpath(__file__)),"helperutil.log")
  #logging.basicConfig(filename=log_file,level=logging.DEBUG)
  logging.info("############Check Router Health ###################")
  logging.info("checkServiceStatus-Method")
  try:
    res = requests.get(baseUrl+"/v1/servers/self/up",verify=False)
    logging.info(res)
    return res.status_code, res.text
  except Exception as err:
    logging.debug("Printing Error: >>>>>>>>>-------------------<<<<<<<<<<<<")
    logging.error (err)
    return 503 , "Router/MP went into invalid state"
  return res.status_code
def getUUID(baseUrl):
  res = requests.get(baseUrl+"/v1/servers/self",verify=False).json()['uUID']
  return res

def write_uuid_to_file(filename,data):
  try:
    with open(filename, "w+") as fp:
      for d in data:
        fp.write(d)
      fp.write("\n")
  except Exception as err:
    logging.error("File write error in write_uuid_to_file method")
    logging.error(err)

def readUUID_component(filename):
  with open(filename) as f:
    content = f.readline()
  #f = open(filename, "r")
  #print (content)
  return str(content).strip()

def remove_server_uuid(router_uuid,baseUrl,username,password,pod,compType,region):
  payload = {'action':'remove','uuid':router_uuid,'region':region,'type':compType,'pod':pod}
  headers = {'content-type': 'application/x-www-form-urlencoded'}
  #print ("#####################")
  #print (compType)
  #print (router_uuid)
  #print (pod)
  #print (region)
  #print (baseUrl)
  logging.info("##########Remove_router_UUID_Method###########")
  logging.info(baseUrl+"/v1/servers?pod="+pod+"&"+"type="+compType)
  #print (baseUrl+"/v1/servers?pod="+pod+"&"+"type="+compType)
  res = requests.post(baseUrl+"/v1/servers", auth=(username,password),verify=False,data=payload,headers=headers)
  #print (res.text)
  logging.info("MS Response for action Remove : {}".format(res.text))
  return res.status_code,res.text

def add_router_uuid(router_uuid,baseUrl,username,password,pod,compType,region):
  payload = {'action':'add','uuid':router_uuid,'region':region,'type':compType,'pod':pod}
  headers = {'content-type': 'application/x-www-form-urlencoded'}
  logging.info("##########Add_router_UUID_Method###########")
  logging.info(baseUrl+"/v1/servers?pod="+pod+"&"+"type="+compType)
  res = requests.post(baseUrl+"/v1/servers", auth=(username,password),verify=False,data=payload,headers=headers)
  logging.info("MS Response for action Add : {}".format(res.text))

def get_org_list(region,pod,baseUrl,username,password):
  orgs=[]
  orgJson = requests.get(baseUrl+"/v1/regions/"+region+"/pods/"+pod+"/o",auth=(username,password),verify=False).json()
  for org in orgJson:
    orgs.append(org['organization'])
  return orgs

def get_env_list(org,baseUrl,username,password):
  envsjson = requests.get(baseUrl+"/v1/o/"+org+"/e",auth=(username,password),verify=False).json()
  return envsjson

def associate_mp_org(baseUrl,org,env,uuid,username,password):
  logging.info("##########associate_mp_org_Method###########")
  logging.info("Associating ORG {} and ENV {} with MP {} ".format(org,env,uuid))
  payload = {'action':'add','uuid':uuid}
  headers = {'content-type': 'application/x-www-form-urlencoded'}
  result = requests.post(baseUrl+"/v1/o/"+org+"/e/"+env+"/servers",auth=(username,password),verify=False,data=payload,headers=headers,timeout=40)
  #logging.info("POST Response {}".format(result.text))
  #print ("POST Response {}".format(result.text))
  #print ("POST Response code{}".format(result.status_code))
  return result.status_code
  #return requests.post(baseUrl+"/v1/o/"+org+"/e/"+env+"/servers",auth=(username,password),verify=False,data=payload,headers=headers)

def thread_handler_associate(baseUrl,uuid,username,password,region,pod,divide_count_start,divide_count_stop):
  orgs_list = get_org_list(region,pod,baseUrl,username,password)
  #print ("Inside thread_handler_associate Method")
  for org in orgs_list[divide_count_start:divide_count_stop]:
    #print ("ORG ------------>>>>>> {}".format(org))
    try:
      env_list = get_env_list(org,baseUrl,username,password)
      for env in env_list:
        print ("ORG---------ENV ------------>>>>>> {} {}".format(org,env))
        if env:
          result = associate_mp_org(baseUrl,org,env,uuid,username,password)
          #print ("rsponse from associate method {}".format(result))
          if result!=200:
            #errorOrgsList.append({"Org":org,"Env":env})
            logging.error("ERROR ORG ------------> {}".format(org))
    except Exception as err:
      logging.error (err)
      logging.error("Error while associating Organisation: %s",org)

def disassociate_mp_org(baseUrl,org,env,uuid,username,password):
  logging.info("##########Disassociate_mp_org_Method###########")
  #print ("disassociate_mp_org -Method")
  logging.info("Disassociating ORG {} and ENV {} with MP {} ".format(org,env,uuid))
  payload = {'action':'remove','uuid':uuid}
  headers = {'content-type': 'application/x-www-form-urlencoded'}
  result = requests.post(baseUrl+"/v1/o/"+org+"/e/"+env+"/servers",auth=(username,password),verify=False,data=payload,headers=headers,timeout=40)
  #logging.info("POST Response {}".format(result))
  #print ("POST Response text{}".format(result.text))
  #print ("POST Response code{}".format(result.status_code))

  return result.status_code
  #return requests.post(baseUrl+"/v1/o/"+org+"/e/"+env+"/servers",auth=(username,password),verify=False,data=payload,headers=headers)

def thread_handler_disassociate(baseUrl,uuid,username,password,region,pod,divide_count_start,divide_count_stop):
  orgs_list = get_org_list(region,pod,baseUrl,username,password)
  #print ("Inside thread_handler_disassociate Method")
  for org in orgs_list[divide_count_start:divide_count_stop]:
    #print ("ORG ------------>>>>>> {}".format(org))
    try:
      env_list = get_env_list(org,baseUrl,username,password)
      for env in env_list:
        #print ("ORG ---------ENV ------------>>>>>> {} {}".format(org,env))
        logging.info("ORG ---------ENV ------------>>>>>> {} {}".format(org,env))
        if env:
          result = disassociate_mp_org(baseUrl,org,env,uuid,username,password)
          #print ("rsponse from associate method {}".format(result))
          if result!=200:
          #   errorOrgsList.append({"Org":org,"Env":env})
            logging.error("ERROR ORG ------------> {}".format(org))
    except Exception as err:
      logging.error("Error while disassociating Organisation: %s",org)
      logging.error(err)

def delete_server(baseUrl,uuid,username,password):
  res = requests.delete(baseUrl+"/v1/servers/"+uuid, auth=(username,password),verify=False)
  return res.status_code
   
def list_dead_mp(baseUrl,username,password,pod,compType,region):
  logging.info("list Dead Router/MP Method")
  dead_mp_uuid = []
  mp_servers_raw = requests.get(baseUrl+"/v1/servers?pod="+pod+"&"+"type="+compType, auth=(username,password),verify=False)
  mp_servers_json = json.loads(mp_servers_raw.text)
  #print (router_servers_json)
  for i in mp_servers_json:
    logging.info ("Router/MP UUID {} and its UP status {}".format(i['uUID'],i['isUp']))
    #logging.info ("MP up Status {}".format(i['isUp']))
    if (str(i['isUp']) == "False"):
      dead_mp_uuid.append(i['uUID'])
      #logging.info ("Dead MP UUID {}".format(i['uUID']))
  #print (dead_routers_uuid)
  return dead_mp_uuid




