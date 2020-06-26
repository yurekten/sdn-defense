import json

import requests

from configuration import HTTP_DEFAULT_HEADER, HTTP_URL

classifier_chain_url = HTTP_URL + "/add_classifier_rules"

result = requests.post(classifier_chain_url, data=json.dumps("classifier_rules"), headers=HTTP_DEFAULT_HEADER)
if result.status_code == 200 or result.status_code == 201:
    print("Classifier rules are deployed to OVS swithes")
    # r1 = json.loads(result.content)
    # print(r1, r1["id"])
else:
    print("Can not listed result from %s: " % (classifier_chain_url,), result)
