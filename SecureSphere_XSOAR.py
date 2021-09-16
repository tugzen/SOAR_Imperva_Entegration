import _json
import requests
import base64
import urllib3
import dateparser
import traceback
from collections import OrderedDict
from typing import Any, Dict, Tuple, List, Optional, Union, cast




'''CONSTANTS'''

URL='https://<IP>:8083/SecureSphere/api/v1/auth/session'

class ImpervaApi:
   
    def __init__(self, username,password):
        self.username=username
        self.password=password



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
        print('restart basladi')
        login_request = self.login()
        #print(login_request)
        command_results=[]
        if login_request['success']:
            urlagent=f'https://10.115.206.53:8083/SecureSphere/api/v1/conf/agents/{agentname}/restart'
            response_from_api=requests.post(urlagent,cookies={'JSESSIONID': login_request["session-id"]}, verify=False)
            #print(response_from_api)
            #print('Finished')
            if "200" in str(response_from_api):
                action_result={"agentname":agentname,"Status":"Agent successfully restarted"}
                #return action_result
            elif "500" in str(response_from_api):
                action_result={"agentname":agentname,"Status":"Agent could not found"}
                #return action_result
            else:
                action_result={"agentname":agentname,"Status":"Unkown"}
                #return action_result
            print('test1414141')
            #print (action_result)
            #action_result=json.dumps(action_result,indent=4)
            print (action_result)
            command_results=CommandResults(
                readable_output=f'##{action_result}',
                outputs_prefix='SecureSphere.Details',
                outputs_key_field='Status',
                outputs=action_result
                )
            return_results(command_results)

    def agent_details(self,agentname):
        print('test error')
        login_request = self.login()
        print(login_request)
        command_results=[]
        if login_request['success']:
            urlagent=f'https://10.115.206.53:8083/SecureSphere/api/v1/conf/agents/{agentname}/GeneralDetails'
            response = requests.get(urlagent, cookies={'JSESSIONID': login_request["session-id"]}, verify=False)
          
            response_from_api=response.json()
            
            print(response_from_api)
            
            print (response_from_api)

           

            command_results=CommandResults(
                readable_output=f'##{response_from_api}',
                outputs_prefix='SecureSphere.Details',
                outputs_key_field='test',
                outputs=response_from_api
                )
            return_results(command_results)




def test_module(username,password):
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type name: ``str``
    :param name: name to append to the 'Hello' string

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    # INTEGRATION DEVELOPER TIP
    # Client class should raise the exceptions, but if the test fails
    # the exception text is printed to the Cortex XSOAR UI.
    # If you have some specific errors you want to capture (i.e. auth failure)
    # you should catch the exception here and return a string with a more
    # readable output (for example return 'Authentication Error, API Key
    # invalid').
    # Cortex XSOAR will print everything you return different than 'ok' as
    # an error

    credentials = username + ":" + password
    #print(credentials)
    credentials_bytes = credentials.encode('ascii')
    base64_bytes = base64.b64encode(credentials_bytes)
    encoded_credentials = base64_bytes.decode('ascii')
    #print(encoded_credentials)
    authorization_string = 'Basic' + " " + encoded_credentials
    # headers = {'Authorization':y}
    # print (headers)

    headers = {'Authorization': f'Basic "{encoded_credentials}"'}
    response = requests.post(URL, headers={'Authorization': authorization_string}, verify=False)

#    session_id = response.json()['session-id']
#    cookie = session_id.split(";")[0]
#    x = cookie.split("=")[0]
#    y = cookie.split("=")[1]
    deneme=[username,password]
    try:
        response.json()['session-id']
    except:
        return 'Credentials are not correct'

    return 'ok'

def main():
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    username = demisto.params().get('username')
    password = demisto.params().get('password')
    args=demisto.args()
    test=ImpervaApi(username,password)
    test.encoding()

    # get the service API url
    #base_url = urljoin(demisto.params()['url'], '/api/v1')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)


    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(username,password)
            return_results(result)


        elif demisto.command() == 'securesphere-get-agent-details':
            #default_threshold_ip = int(demisto.params().get('threshold_ip', '65'))
            agentname=args.get('name')
            return_results(test.agent_details(agentname))

        elif demisto.command() == 'securesphere-restart-agent':
            #default_threshold_domain = int(demisto.params().get('threshold_domain', '65'))
            agentname=args.get('name')
            return_results(test.agent_restart(agentname))



    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()


