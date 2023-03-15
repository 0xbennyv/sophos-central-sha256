import requests
import json


class Authenticate():

    def whoami(token):
        uri = 'https://api.central.sophos.com/whoami/v1'
        h = {'Authorization': f'Bearer {token}'}
        r = requests.get(uri, headers=h)
        if r.status_code == 200:
            j = json.loads(r.text)
            tenant_id = j['id']
            tenant_type = j['idType']
            if 'dataRegion' in j['apiHosts']:
                data_region = j['apiHosts']['dataRegion']
            else:
                data_region = j['apiHosts']['global']
            return tenant_id, tenant_type, data_region
        else:
            print("Error: Unable to obtain whoami details")

    def auth(client_id, client_secret):
        uri = "https://id.sophos.com/api/v2/oauth2/token"

        d = {'grant_type': 'client_credentials',
             'client_id': client_id,
             'client_secret': client_secret,
             'scope': 'token'
             }
        r = requests.post(uri, data=d)

        if r.status_code == 200:
            j = json.loads(r.text)
            jwt = j['access_token']
            tenant_id, tenant_type, data_region = Authenticate.whoami(jwt)
            return jwt, tenant_id, tenant_type, data_region

        else:
            print("Error: Authentication failed")
            return False
