import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_oauth_token(oath_endpoint,username,password):
    r = requests.get(oath_endpoint,auth=(username,password),verify=False)
    if r.status_code == 200:
        data = json.loads(r.text)
        return data['access_token']

def get_mp_XProperty(endpoint,access_token):
    headers = {
        'Accept':'application/json',
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(access_token)
        }
    r = requests.get(endpoint,verify=False,headers=headers)
    if r.status_code == 200:
        data = json.loads(r.text)
        for each_property in data['d']['results']:
            if each_property['name'] == 'apiportal.onboarding.apiruntime_prod.mps':
                return True
        return False
    else:
        return False

def validate_dt_ep(dt_oauth_host,dt_apiportal_host,dt_oauth_username,dt_oauth_password):
    oath_endpoint = 'https://{}/oauth/token?grant_type=client_credentials'.format(dt_oauth_host)
    dt_endpoint = 'https://{}/apiportal/operations/1.0/Configuration.svc/XPropertys'.format(dt_apiportal_host)
    XProperty = '(\'apiportal.onboarding.apiruntime_prod.mps\')'
    access_token = get_oauth_token(oath_endpoint,dt_oauth_username,dt_oauth_password)
    if get_mp_XProperty(dt_endpoint,access_token):
        return True
    else:
        return False