from django.shortcuts import render
from ldap3 import Server, Connection, ALL
import datetime,time
import re
import base64
import requests
import hmac
from hashlib import sha256
import json
class operate_AD():
    def __init__(self,Domain,User,Password):
        self.domain=Domain
        self.user=User
        self.pwd=Password
        self.DC=','.join(['DC=' + dc for dc in Domain.split('.')])
        # self.pre = Domain.split('.')[0].upper()
        self.server = Server(self.domain, use_ssl=True,get_info=ALL)
        self.conn = Connection(self.server, user=self.user, password = self.pwd, auto_bind = True,)
        self.u_time=datetime.date.today()

    def Get_All_UserInfo(self,username,password):
        '''
        查询组织下的用户
        org: 组织，格式为：aaa.bbb 即bbb组织下的aaa组织，不包含域地址
        '''
        att_list = ['displayName', 'userPrincipalName', 'userAccountControl', 'sAMAccountName', 'pwdLastSet','mail']
        # org_base = ','.join(['OU=' + ou for ou in org.split('.')]) + ',' + self.DC
        res = self.conn.search(search_base=self.DC, search_filter='(mail={accounter})'.format(accounter=username),
                               attributes=att_list, paged_size='50', search_scope='SUBTREE',)
        # print(res)
        if res:
            for each in self.conn.response:
                # print(each['dn'])
                user = []
                if len(each) == 5:
                    user = [each['dn'], each['attributes']['sAMAccountName'], each['attributes']['displayName'],]
                    name=user[2]
                    self.conn2 = Connection(self.server, user=name, password=password, auto_bind=True, )
                    if self.conn2:
                        return name
        else:
            print('查询失败: ', self.conn.result['description'])
            return None

    def Get_All_GroupInfo(self):
        '''
        查询组织下的用户
        org: 组织，格式为：aaa.bbb 即bbb组织下的aaa组织，不包含域地址
        '''

        att_list = ['cn', 'member', 'objectClass', 'userAccountControl','SamAccountName', 'description']
        # org_base = ','.join(['OU=' + ou for ou in org.split('.')]) + ',' + self.DC
        res = self.conn.search(search_base=self.DC, search_filter='(objectclass=group)', attributes=att_list,
                               paged_size='', search_scope='SUBTREE')
        if res:
            OperationMD=[]

            for each in self.conn.response:
                r='CN=(.*?),OU=(.*?),OU=(.*?),OU=(.*?),OU=(.*?),OU=(.*?),DC=(.*?),DC=(.*?)'
                if len(each) == 5:
                    for member in each['attributes']['member']:
                        group = [each['attributes']['sAMAccountName'], member, self.u_time]
                        if (group[0])=="Operations_MD_KPI_Visualization":
                            a=re.findall(r,group[1])
                            OperationMD.append(a[0][0].replace("\\",""))

            return [OperationMD]
        else:
            print('查询失败: ', self.conn.result['description'])
            return None

def login(request):
    context={}
    a=request.COOKIES
    b=request.session.items()
    url = request.build_absolute_uri(request.get_full_path())
    print(a)
    print(b)
    if request.method == "POST":
        eusername = request.POST['username']
        epassword = request.POST['password']
        act = operate_AD('bitzer.cn', 's00003', '123,.abc')
        user = act.Get_All_UserInfo(eusername, epassword)
        if user:
            ERP_url=ERP(username=user)
            context["url3"]=ERP_url
            return render(request, 'ERP.html',context)
        else:
            context['error']= 'Enter valid username or password...'
            return render(request,'login.html',context)
    return render(request,'login.html')

def ERP(username):
    # get access token
    url1 = 'https://api.diwork.com/open-auth/selfAppAuth/getAccessToken'
    t=round(time.time()*1000)
    X_Signature='appKey'+'04b1bd1223f64d6cbef5e92ade9acd8d'+'timestamp'+str(t)
    XClientId='a33c54c7d4b14dbda0564c043cea02cd'
    signature=getSignature(XClientId=XClientId,X_Signature=X_Signature)
    params = {'appKey': "04b1bd1223f64d6cbef5e92ade9acd8d", 'timestamp': t, 'signature':signature}  # 提交数据
    request = requests.get(url1, params=params)  # 请求处理
    response = request.json()
    token=response["data"]["access_token"]
    # get ERP login code
    url2='https://api.diwork.com/yonbip/yht/getThirdLoginCode?access_token={token}'.format(token=token)
    body={
    "thirdUcId": "ntfrjemn",
    "userId": username,
    "mobile": "",
    "email": "",
    "userName": "",
    "userCode": ""}

    headers = {'content-type': "application/json"}
    response2 = requests.post(url2, data=json.dumps(body), headers=headers)
    code=response2.json()["data"]["code"]
    # ERP_login_url
    url3='https://euc.diwork.com/cas/thirdOauth2CodeLogin?thirdUCId=ntfrjemn&code={code}&service=https://yonsuite.diwork.com/login'.format(code=code)
    return url3

def getSignature(XClientId, X_Signature):
    XClientId = XClientId.encode('utf-8')
    X_Signature = X_Signature.encode('utf-8')
    signature = base64.b64encode(hmac.new(XClientId, X_Signature, digestmod=sha256).digest()).decode()
    return signature


from simple_sso.sso_server.models import Consumer,Token