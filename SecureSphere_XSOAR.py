import _json
import requests
import base64
import urllib3
import dateparser
import traceback
from collections import OrderedDict
from typing import Any, Dict, Tuple, List, Optional, Union, cast




'''CONSTANTS'''

URL='https://10.115.206.53:8083/SecureSphere/api/v1/auth/session'

class ImpervaApi:
    # credentials= '{tugrul.zengin}{1841tZ1q!1841}'
    # credentials_bytes = credentials.encode('ascii')
    # base64_bytes = base64.b64encode(credentials_bytes)
    # base64_credentials = base64_bytes.decode('ascii')
#encoded_credentials= base64.

#print(base64_credentials)

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
            #print(response.json())
            #print('Finished')
            response_from_api=response.json()
            #k['test']='Deneme123'
            #k['test2']='Deneme2'
            #k=OrderedDict(reversed(list(k.items())))
            print(response_from_api)
            #response_from_api=str(k).replace("'", '"')
            #response_from_api=k
            #response_from_api={ "status": { "general-status": "Running", "start-time": "2021-09-07 10:03:27.0", "last-status-update": "Thu Sep 09 14:38:49 AST 2021", "last-activity": "1631187534064", "throughput-kb": "40", "connections-per-sec": "0", "hits-per-sec": "5", "cpu-utilization": "0" }, "properties": { "Agent Version": "14.1.0.10.0.562097", "Platform": "AMD64", "Hostname": "DTEKEBADBT1", "Operating System": "Microsoft Windows Server 2016 Standard Edition, 64-bit", "Kernel Patch": " (build 14393)" }, "general-info": { "name": "DTEKEBADBT1", "ip": "10.115.210.50", "creation-time": "2020-07-17 16:03:33.0", "manual-settings-activation": "Off" }, "test": "Deneme123" }

            print (response_from_api)

            #test_format0

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

        elif demisto.command() == 'helloworld-say-hello':
            return_results(say_hello_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-search-alerts':
            return_results(search_alerts_command(client, demisto.args(name)))

        elif demisto.command() == 'helloworld-get-alert':
            return_results(get_alert_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-update-alert-status':
            return_results(update_alert_status_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-scan-start':
            return_results(scan_start_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-scan-status':
            return_results(scan_status_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-scan-results':
            return_results(scan_results_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()


