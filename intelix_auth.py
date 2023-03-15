import requests
import base64


class Authenticate:
    def auth(intelix_client_id, intelix_client_secret):
        creds = f"{intelix_client_id}:{intelix_client_secret}"
        t = base64.b64encode(creds.encode("UTF-8")).decode("ascii")
        d = {"grant_type": "client_credentials"}
        h = {
            "Authorization": f"Basic {t}",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        r = requests.post(
            "https://api.labs.sophos.com/oauth2/token", headers=h, data=d)
        r = r.json()
        if 'access_token' in r:
            return r["access_token"]
        else:
            print("Error Obtaining SophosLabs Intelix Token")
            quit()
