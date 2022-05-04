from django.shortcuts import render
# from azure.identity import ClientSecretCredential
# from azure.mgmt.media import AzureMediaServices
import os
# Create your views here.
def login(request):
    context={}
    if request.method == "POST":
        eusername = request.POST['username']
        epassword = request.POST['password']
    return render(request,'login.html')


def test():
    # Tenant ID for your Azure Subscription
    TENANT_ID = "321af56c-a08e-4e2d-b23c-cc0a50976a0c"

    # Your Application Client ID of your Service Principal
    CLIENT_ID = "a3c3cbd0-cfad-4833-8b20-c4df784b4f1f"

    # Your Service Principal secret key
    CLIENT_SECRET = "6QS8Q~1mPUYeZk6Ad5x1h5zqUm5gatz_.dE27cOr"

    # Your Azure Subscription ID
    SUBSCRIPTION_ID = "1003200183102672"

    # Your Resource Group name
    RESOURCE_GROUP_NAME = "b17a5e15-9341-4397-9c8a-7f820eacfc16"

    # Your Azure Media Service account name
    ACCOUNT_NAME = "pan.wenfang"

    # credentials = ClientSecretCredential(TENANT_ID, CLIENT_ID, CLIENT_SECRET, authority="login.chinacloudapi.cn")
    # print(credentials)
    # # The Azure Media Services Client
    # client = AzureMediaServices(credentials, SUBSCRIPTION_ID, base_url="https://management.chinacloudapi.cn")


    # Now that you are authenticated, you can manipulate the entities.
    # For example, list assets in your Media Services account
    # assets = client.assets.list(RESOURCE_GROUP_NAME, ACCOUNT_NAME)

    # for i, r in enumerate(assets):
    #     print(r)
if __name__ == '__main__':
    test()