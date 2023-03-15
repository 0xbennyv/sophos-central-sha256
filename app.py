from optparse import OptionParser
from os import path
from time import strftime
import csv
import requests
import json
import central_oauth
import intelix_auth
import central_edb

# Sophos Central Credentials
central_client_id = ""
central_client_secret = ""
# Intelix Credentials
intelix_client_id = ""
intelix_client_secret = ""
# Virus Total Credentials
vt_api = ""


def check_vt(sha):
    u = "https://www.virustotal.com/vtapi/v2/file/report"
    params = {"apikey": f"{vt_api}", "resource": f"{sha}"}
    r = requests.get(u, params=params)
    if r.status_code == 200:
        j = json.loads(r.text)
        return j


def check_intelix(token, sha):
    u = f"https://de.api.labs.sophos.com/lookup/files/v1/{sha}"
    h = {"Authorization": f"{token}"}
    r = requests.get(u, headers=h)
    j = r.json()
    if "reputationScore" in j:
        if j["reputationScore"] <= 19:
            # Malware
            response = True
        elif j["reputationScore"] <= 29:
            # PUA (potentially unwanted application)
            response = True
        elif j["reputationScore"] <= 69:
            # Unknown/suspicious
            response = False
        elif j["reputationScore"] <= 100:
            # Known good
            response = False

    if "error" in j:
        print(f'Error: {j["error"]}')
    if "message" in j:
        print(j["message"])
    return response


def add_to_central(sha, comment):
    if tenant_type == 'tenant':
        # use the api_creds to go to the correct URL
        u = f"{data_region}/endpoint/v1/settings/blocked-items"
        # Set the headers.
        h = {"Authorization": f"Bearer {jwt}", "X-Tenant-ID": f"{tenant_id}"}
        # Set the params
        p = {
            "type": "sha256",
            "properties": {"sha256": f"{sha}"},
            "comment": f"{comment}",
        }
        # Run the initial request
        r = requests.post(u, headers=h, json=p)
        if r.ok:
            print(f"Successfully added SHA256")
        else:
            print(f"Error adding SHA256")

    elif tenant_type == 'organization':
        for tenant in tenants:
            # use the api_creds to go to the correct URL
            u = f"{tenant['apihost']}/endpoint/v1/settings/blocked-items"
            # Set the headers.
            h = {"Authorization": f"Bearer {jwt}",
                 "X-Tenant-ID": f"{tenant['id']}"}
            # Set the params
            p = {
                "type": "sha256",
                "properties": {"sha256": f"{sha}"},
                "comment": f"{comment}",
            }
            # Run the initial request
            r = requests.post(u, headers=h, json=p)
            if r.ok:
                print(f"Successfully added SHA256 to Tenant: {tenant['id']}")
            else:
                print(f"Error adding SHA256 to Tenant: {tenant['id']}")


def write_output(outfile, sha, outcome):
    with open(outfile, "a") as f:
        csv_out = csv.writer(f, delimiter=",", quotechar='"',
                             quoting=csv.QUOTE_MINIMAL)
        csv_out.writerow([sha, outcome])


def parse_objects(**kwargs):
    # If filename is set loop through
    if kwargs.get("filename"):
        # If output is set then add the filename
        if kwargs.get("output"):
            out_file = f'{strftime("%Y_%m_%d_%H_%M_%S")}.csv'
        # Open CSV file to read
        f = open(kwargs.get("filename"))
        # read
        reader = csv.reader(f)
        # Get the Intelix Token prior to loop to avoid re-auth
        if kwargs.get("intelix"):
            # Get the first intelix token here.
            intelix_token = intelix_auth.Authenticate.auth(
                intelix_client_id, intelix_client_secret
            )
        # Loop through csv
        for row in reader:
            # If Virus Total is selected
            if kwargs.get("virustotal"):
                # Run check_vt to get a response
                vt = check_vt(row[0])
                # If the response code is 1 then it's been scanned
                if vt["response_code"] == 1:
                    if vt["scans"]["Sophos"]["detected"]:
                        # Detected So Skip
                        outcome = "Already Known bad by SOPHOS"
                    else:
                        # Known to Virus total not detected by SOPHOS on VirusTotal
                        add_to_central(row[0], row[1])
                        outcome = "Added to SOPHOS Central"
                else:
                    # Not known to Virus Total so add it to Central
                    add_to_central(row[0], row[1])
                    outcome = "Added to SOPHOS Central"
            elif kwargs.get("intelix"):
                # Run check against Intelix
                res = check_intelix(intelix_token, row[0])
                if res:
                    outcome = "Already Known bad by SOPHOS"
                else:
                    add_to_central(kwargs.get("sha"), kwargs.get("comment"))
                    outcome = "Added to SOPHOS Central"
            # if virus total isn't set
            else:
                # post to central
                add_to_central(row[0], row[1])
                outcome = "Added to SOPHOS Central"
            # if output is set then run the output function
            if kwargs.get("output"):
                write_output(out_file, row[0], outcome)
        # Close File
        f.close()

    # If SHA is set then add the one off
    if kwargs.get("sha"):
        # If output is set then add the filename
        if kwargs.get("output"):
            out_file = f'{strftime("%Y_%m_%d_%H_%M_%S")}.csv'
        # If Virus Total is selected
        if kwargs.get("virustotal"):
            # Run check_vt to get a response
            vt = check_vt(kwargs.get("sha"))
            # If the response code is 1 then it's been scanned
            if vt["response_code"] == 1:
                if vt["scans"]["Sophos"]["detected"]:
                    # Detected So Skip
                    outcome = "Already Known bad by SOPHOS"
                else:
                    # Known to Virus total not detected by SOPHOS on VirusTotal
                    add_to_central(kwargs.get("sha"), kwargs.get("comment"))
                    outcome = "Added to SOPHOS Central"
            else:
                # Not known to Virus Total so add it to Central
                add_to_central(kwargs.get("sha"), kwargs.get("comment"))
                outcome = "Added to SOPHOS Central"
        elif kwargs.get("intelix"):
            # Run check against Intelix
            intelix_token = intelix_auth.Authenticate.auth(
                intelix_client_id, intelix_client_secret
            )
            res = check_intelix(intelix_token, kwargs.get("sha"))
            if res:
                outcome = "Already Known bad by SOPHOS"
            else:
                add_to_central(kwargs.get("sha"), kwargs.get("comment"))
                outcome = "Added to SOPHOS Central"
        # if virus total isn't set
        else:
            # post to central
            add_to_central(kwargs.get("sha"), kwargs.get("comment"))
            outcome = "Added to SOPHOS Central"
        # If output is set send it to the function to write the CSV
        if kwargs.get("output"):
            write_output(out_file, kwargs.get("sha"), outcome)


if __name__ == "__main__":
    # Get the stuff you need
    jwt, tenant_id, tenant_type, data_region = central_oauth.Authenticate.auth(
        central_client_id, central_client_secret
    )
    if tenant_type == "organization":
        tenants = central_edb.get_tenants(jwt, tenant_id)

    # Setup usage
    usage = "usage: --file FILENAME [--intelix OR --virustotal] --sha SHA --comment COMMENT --output"
    # Set Usage and initialise option parser
    parser = OptionParser(usage=usage)
    # Set the options
    parser.add_option(
        "-f",
        "--file",
        dest="filename",
        help="File to import to SOPHOS Central, this should be a CSV formatted: sha256, comment",
    )
    parser.add_option(
        "-o",
        "--output",
        dest="output",
        help="Output the outcome of each hash",
        action="store_true",
        default=False,
    )
    parser.add_option(
        "-s",
        "--sha",
        dest="sha",
        help="A SHA to quickly add to SOPHOS Central if no CSV is provided",
    )
    parser.add_option(
        "-c",
        "--comment",
        dest="comment",
        help="A comment for the SHA that's being added to SOPHOS Central used in conjunction with -sha",
    )
    parser.add_option(
        "-v",
        "--virustotal",
        dest="virustotal",
        help="Check for detection against virus total before submitting to SOPHOS Central",
        action="store_true",
        default=False,
    )

    parser.add_option(
        "-i",
        "--intelix",
        dest="intelix",
        help="Check for detection against SophosLabs Intelix before submitting to SOPHOS Central",
        action="store_true",
        default=False,
    )

    (options, args) = parser.parse_args()
    # If SHA is set then do a once off
    if options.sha:
        # If description is none then bail out
        if options.comment is None:
            # Error out
            parser.error(msg="A comment is needed when parsing a SHA")
        # Else Add to central
        parse_objects(
            sha=options.sha,
            comment=options.comment,
            output=options.output,
            virustotal=options.virustotal,
            intelix=options.intelix,
        )
    # Else if filename is set loop through.
    elif options.filename:
        # check to see if a path exists
        if path.isfile(path=options.filename):
            # Add to central
            parse_objects(
                filename=options.filename,
                output=options.output,
                virustotal=options.virustotal,
                intelix=options.intelix,
            )
        # If path doesn't exist
        else:
            # Error out
            parser.error(msg="Path doesn't exist")
    else:
        parser.error(msg="Needed arguments missing")
