#!/usr/bin/env bash
set -e  

echo "Running az login"
az login --service-principal -u ${AZURE_CLIENT_ID} -p ${AZURE_CLIENT_SECRET} -t ${AZURE_TENANT_ID}
curl https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.gpg
sudo mv microsoft.gpg /etc/apt/trusted.gpg.d/microsoft.gpg
sudo sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-ubuntu-$(lsb_release -cs)-prod $(lsb_release -cs) main" > /etc/apt/sources.list.d/dotnetdev.list'
sudo apt-get update
echo "Installing Azure Function Core tools"
sudo apt-get install azure-functions-core-tools -y 
sudo apt-get install azure-cli -y
cd ${root_dir}/vmss-function-app
echo "Publishing code to funcation app"
func azure functionapp publish ${func_app_name} --python
echo "Code publish complete"