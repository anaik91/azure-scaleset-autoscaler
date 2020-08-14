"""
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
      ExecStop=/bin/sudo /bin/python3.6 /opt/autoscale/python/remove_uuid.py -w "{{protocol}}" -o "{{port}}" -i "{{ms_ip}}" -e "{{username}}" -p "{{password}}" -r "{{region}}" -n "{{pod}}"
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