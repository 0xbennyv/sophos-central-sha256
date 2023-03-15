import requests
import json


def get_tenants(token, org_id):
    uri = 'https://api.central.sophos.com/organization/v1/tenants?pageTotal=true'
    h = {'Authorization': f'Bearer {token}',
         'X-Organization-ID': org_id}
    r = requests.get(uri, headers=h)
    tenants = []
    if r.status_code == 200:
        j = json.loads(r.text)
        if 'items' in j:
            for tenant in j['items']:
                tenants.append(
                    {'id': tenant['id'], 'apihost': tenant['apiHost']}
                )
        if j['pages']['total'] > 1:
            i = 2
            while i <= j['pages']['total']:
                uri = f'https://api.central.sophos.com/organization/v1/tenants?page={i}'
                h = {'Authorization': f'Bearer {token}',
                     'X-Organization-ID': org_id}
                r = requests.get(uri, headers=h)
                if r.status_code == 200:
                    j = json.loads(r.text)
                    if 'items' in j:
                        for tenant in j['items']:
                            tenants.append(
                                {'id': tenant['id'],
                                    'apihost': tenant['apiHost']}
                            )
                i += 1
        return tenants
    else:
        print("Error: Unable to obtain tenant details")
