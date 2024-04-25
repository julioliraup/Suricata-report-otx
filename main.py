import re
from OTXv2 import OTXv2, InvalidAPIKey, BadRequest, RetryError
import IndicatorTypes
import requests, json

# Reference https://github.com/AlienVault-OTX/OTX-Python-SDK/blob/master/examples/misp_json_to_otx.py

# SETTINGS
# Your API key
API_KEY = ''
FILENAME = ''

log_file = open(FILENAME,'r')
for log in log_file:
    action_pattern = re.search('\[(.*?)\]', log)
    description_pattern = re.search('\[\d+:\d+:\d+\] (.*?) \[\*\*\]', log)
    classification_pattern = re.search('Classification: (.*?)\]', log)
    ip_pattern = re.search('\{.*?\} ([\d.:a-fA-F]+)', log)

    action = action_pattern.group(1)
    description = description_pattern.group(1)
    classification = classification_pattern.group(1)
    ip = ip_pattern.group(1)

    OTX_SERVER = 'https://otx.alienvault.com/'
    otx = OTXv2(API_KEY, server=OTX_SERVER)
    response = otx.create_pulse(name=description, indicators=[ip], references=[], tlp='white', description=f"{classification} from {ip} Pulse imported from incident log", tags = [classification])
    print ("Made pulse with response: " + str(response))

log_file.close()