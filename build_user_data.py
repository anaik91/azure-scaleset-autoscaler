from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
import requests,base64
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from jinja2 import Template

credential = DefaultAzureCredential()

cloud_init_template="""
#cloud-config
users:
  - name: concourseci
    ssh-authorized-keys:
      - {{public_key_data}}
    sudo:  ['ALL=(ALL) NOPASSWD:ALL']
    shell: /bin/bash
    home: /home/concourseci
    groups: wheel

write_files:
  - content: |
      [Unit]
      Description=Start_stop
      After=network.target
      [Service]
      Type=oneshot
      RemainAfterExit=true
      ExecStartPre=/bin/sleep 10
      ExecStart=/bin/sudo /bin/python3.6 /opt/autoscale/python/add_uuid.py -w "{{protocol}}" -o "{{port}}" -i "{{ms_ip}}" -e "{{username}}" -p "{{password}}" -r "{{region}}" -n "{{pod}}" -u "{{dynatrace_api_url}}/events" -a "{{dynatrace_api_token}}"
      [Install]
      WantedBy=multi-user.target
    path: /etc/systemd/system/start_stop.service
    permissions: '0644'
  - content: |
      #!/bin/bash
      echo "Custom Property Push Start"
      mkdir -p /opt/apigee/customer/application/
      /usr/bin/keyctl new_session
      azcopy login --identity
      azcopy cp  "https://{{storage_account}}.blob.core.windows.net/custom-properties/custom-properties/{{component_group}}/{{component_name}}.properties" "/opt/apigee/customer/application/{{component_name}}.properties"
      chown -R apigee:apigee /opt/apigee/customer
      echo "Custom Property Push End"
    path: /opt/autoscale/custom_prop.sh
    permissions: '0755'
  - content: |
      #!/bin/bash
      echo "Exporting Logs"
      log_folder=$(curl -H Metadata:true "http://169.254.169.254/metadata/instance/compute/name?api-version=2017-08-01&format=text")
      /usr/bin/keyctl new_session
      azcopy login --identity
      azcopy cp "/opt/apigee/var/log" "https://{{storage_account}}.blob.core.windows.net/router-vm-logs/$log_folder" --recursive=true
      echo "Exported Logs"
    path: /opt/autoscale/export_logs.sh
    permissions: '0755'

runcmd:
  - sudo /bin/bash /opt/autoscale/files/expand_disk.sh
  - sudo /bin/sh /opt/autoscale/files/dynatrace.sh "{{dynatrace_api_url}}/deployment/installer/agent/unix/default/latest?Api-Token={{dynatrace_api_token}}&arch=x86&flavor=default" "/tmp/one_agent.sh" "/opt/autoscale"
  - echo "{{component}}" > /opt/autoscale/python/component_name.txt
  - /bin/python3.6 /opt/autoscale/python/create_silent_config.py -m "{{ms_ip}}" -e "{{username}}" -p "{{password}}" -o "{{port}}" -w "{{protocol}}" -r "{{region}}" -n "{{pod}}" -u "{{dynatrace_api_url}}/events" -a "{{dynatrace_api_token}}"
  - sudo /opt/autoscale/custom_prop.sh
  - sudo /bin/python3.6 /opt/autoscale/python/azure_helpers.py
  - sudo /opt/apigee/apigee-setup/bin/setup.sh -p {{component}} -f /opt/autoscale/python/silent_config
  - sudo /opt/apigee/apigee-service/bin/apigee-all restart
  - /bin/python3.6 /opt/autoscale/python/uuid_generator.py -w http -o "{{uuid_port}}" -i localhost -u "{{dynatrace_api_url}}/events" -a "{{dynatrace_api_token}}" -c {{uuid_retry}}
  - sudo systemctl daemon-reload
  - sudo systemctl enable start_stop.service
  - sudo systemctl -l start start_stop.service
  - sudo /bin/sh /opt/autoscale/files/monit_setup.sh
  - sudo rm -rf /opt/autoscale/python/silent_config
"""
template = Template(cloud_init_template)

def get_auth_token(username,password):
    auth_token = base64.b64encode('{}:{}'.format(username,password).encode('utf-8'))
    auth_token = 'Basic {}'.format(auth_token.decode('utf-8'))
    return auth_token

def get_apigee_region(baseUrl,auth_token):
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': auth_token
    }
    response = requests.get(baseUrl+"/v1/regions",headers=headers,verify=False)
    regions = response.json()
    if len(regions) > 0:
        return regions[0]
    else:
        None
  
def get_apigee_mp_pod(baseUrl,auth_token,region):
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': auth_token
    }
    response = requests.get("{}/v1/regions/{}/pods".format(baseUrl,region),headers=headers,verify=False)
    mp_pod = [i for i in response.json() if 'gateway' in i]
    if len(mp_pod) >0 :
        return mp_pod[0]
    else:
        return None

def fetch_secrets(vault_url):
    client = SecretClient(vault_url=vault_url, credential=credential)
    data = {
    'sshpublickey': client.get_secret('sshpublickey').value,
    'mspassword' : client.get_secret('mspassword').value,
    'msusername' : client.get_secret('msusername').value,
    'dynatraceapitoken' : client.get_secret('dynatraceapitoken').value,
    'dynatraceapiurl' : client.get_secret('dynatraceapiurl').value
    }
    return data

def get_user_data(ms_ip,vault_uri,storage_account):
    secrets = fetch_secrets(vault_uri)
    apigee_auth_token = get_auth_token(secrets['msusername'],secrets['mspassword'])
    apigee_base_url = 'https://{}'.format(ms_ip)
    apigee_region = get_apigee_region(apigee_base_url,apigee_auth_token)
    apigee_mp_pod = get_apigee_mp_pod(apigee_base_url,apigee_auth_token,apigee_region)
    print('\nApigee Details : \n Region: {} \n Pod : {}'.format(apigee_region,apigee_mp_pod))
    user_data = template.render(
        public_key_data = secrets['sshpublickey'],
        protocol = 'https',
        port = '443',
        ms_ip = ms_ip,
        username = secrets['msusername'],
        password = secrets['mspassword'],
        region = apigee_region,
        pod = apigee_mp_pod,
        dynatrace_api_url = secrets['dynatraceapiurl'],
        dynatrace_api_token = secrets['dynatraceapitoken'],
        storage_account = storage_account,
        component = 'mp',
        component_group = 'mp',
        component_name = 'message-processor',
        uuid_port = 8082,
        uuid_retry = 3
    )
    user_data_b64 = base64.b64encode(user_data.encode('utf-8'))
    #print('\nUser Data Base 64: \n{}'.format(user_data_b64.decode('utf-8')))
    return user_data_b64.decode('utf-8')


if __name__ == '__main__':
    data = fetch_secrets('https://az-mp-pool-002.vault.azure.net/')
    print(data)