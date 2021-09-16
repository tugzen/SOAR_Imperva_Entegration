import _json
import json
import requests
import base64


URL='https://<IP>:8083/SecureSphere/api/v1/auth/session'

class ImpervaApi:
   

    def __init__(self, username,password):
        self.username=username
        self.password=password


#
    def encoding(self):

        credentials= self.username + ":" + self.password
        print (credentials)
        credentials_bytes=credentials.encode('ascii')
        base64_bytes=base64.b64encode(credentials_bytes)
        encoded_credentials=base64_bytes.decode('ascii')
        return encoded_credentials


    def login(self):


        authorization_string='Basic' + " " + self.encoding()
        #headers = {'Authorization':y}
        #print (headers)

        #headers = {'Authorization': f'Basic "{self.encoding()}"'}
        response=requests.post(URL ,headers={'Authorization':authorization_string},verify=False)
        print(response.json())

        session_id=response.json()['session-id']
        cookie=session_id.split(";")[0]
        x=cookie.split("=")[0]

        y=cookie.split("=")[1]


        print(response.json())
        print(x)
        print(y)

        try:
            return {'success':True , 'session-id': y}

        except BaseException as e:
            return {'success':False, 'error':'Could not be logged in'}

    def getreport(self,reportname):
        login_request=self.login()
        print(login_request)
        if login_request['success']:
            urlreport=f'https://10.115.206.53:8083/SecureSphere/api/v1/conf/dbauditreports/{reportname}'
            print(urlreport)
            report = requests.get(urlreport, cookies={'JSESSIONID': login_request["session-id"]}, verify=False)
            print(report.json())
        else:
            print("error")

    def agent_restart(self,agentname):
        login_request = self.login()
        print(login_request)
        if login_request['success']:
            urlagent=f'https://10.115.206.53:8083/SecureSphere/api/v1/conf/agents/{agentname}/restart'
            response=requests.post(urlagent,cookies={'JSESSIONID': login_request["session-id"]}, verify=False)
            print(response)
            print('Finished')

    def agent_details(self,agentname):
        login_request = self.login()
        print(login_request)
        if login_request['success']:
            urlagent=f'https://10.115.206.53:8083/SecureSphere/api/v1/conf/agents/{agentname}/GeneralDetails'
            response = requests.get(urlagent, cookies={'JSESSIONID': login_request["session-id"]}, verify=False)
            #print(response.json())
            k=response.json()
            k2=str(k).replace("'", '"')
            print(k2)
            print('Finished')
            f = open("details.txt", "w")
            f.write(k2)
            f.close()
            print('writing finished')






test = ImpervaApi("<username>", "<password>")
test.encoding()
#print(test.getreport('<reportname>'))
#print (test.agent_restart('<agentname>'))
print(test.agent_details('<agentname>'))


