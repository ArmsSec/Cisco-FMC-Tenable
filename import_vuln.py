#!/usr/bin/env python
from tenable.sc import TenableSC
import configparser
import subprocess

#Parse the config file
configParser = configparser.RawConfigParser()
configParser.read("config.cfg")

address = configParser.get('UserVariables','address')
debug = configParser.getboolean('UserVariables', 'debug')
ip_range = configParser.get('UserVariables','ip_range').split('\n')
page_size = configParser.getint('UserVariables', 'page_size')
fmc = configParser.get('UserVariables','fmc')
delay = configParser.getint('UserVariables', 'delay')
quiet = configParser.getboolean('UserVariables', 'quiet')
#debug variable for testing
staging = False
# open csv for writing
new_vul = open("csvin.txt", "w")
# Login to Tenable.sc
sc = TenableSC(address, debug=debug)

#Login using username and password
#username = os.environ["username"]
#password = os.environ["password"]
#sc.login(username, password, force_session=True)

#login using Token
configParser.read(".env")
TACK = configParser.get('var','TACK')
TSCK = configParser.get('var','TSCK')

### get the vulnerabilities from Tenable
sc.login(access_key=TACK, secret_key=TSCK)
new_vul.write("SetSource, SecurityCenter 6.x\n")
#define the query that will be run on the Tenable.sc API call
for i in ip_range:
    query = {
            "type": "vuln",
            "tool": "vulndetails",
            "sourceType": "cumulative",
            "startOffset": 0,
            "endOffset": page_size,
            "filters":[
                    {
                    "id": "severity",
                    "filterName": "severity",
                    "operator":"=",
                    "type": "vuln",
                    "isPredefined": True,
                    "value": "4,3,2"
                    },
                    {
                    "id": "ip",
                    "filterName": "ip",
                    "operator":"=",
                    "type": "vuln",
                    "isPredefined": True,
                    "value": i.replace("\\n", "\n")
                    }
                ]
            }
    # build a host cache to elimiate redundant commands on the FMC
    host_cache = []
    response = sc.analysis.vulns(type="vuln", sourceType="cumulative", query=query)
    # process the page of data and write to the CSV
    for vulnerability in response:
        #logic in case vulnerability protocol is not supported
        if vulnerability["protocol"].lower() == "icmp":
            port = ""
            protocol = ""
        else:
            port = vulnerability["port"]
            protocol = vulnerability["protocol"].lower()
        if vulnerability["ip"] not in host_cache:
            # this means we are at a new host so we can write a host entry
            host_cache.append(vulnerability["ip"])
            new_vul.write("AddHost, {}\n".format(vulnerability["ip"]))
        #write the vulnerability to the csv for import
        new_vul.write("AddScanResult, {}, \"SecurityCenter 6.x\", {}, {}, {}, \"{}\", \"{}\", \"cve_ids: {}\", \"bugtraq_ids:\"\n".format(
        vulnerability["ip"],
        vulnerability["pluginID"],
        port,
        protocol,
        vulnerability["pluginName"],
        vulnerability["synopsis"],
        vulnerability["cve"].replace(","," ")))
    
new_vul.write("ScanFlush\n")
new_vul.close()

if debug:
    pipe = subprocess.call(["./sf_host_input_agent.pl", "-server={}".format(fmc), "-level=3","-plugininfo=csvin.txt", "csv" ])
else:
    pipe = subprocess.call(["./sf_host_input_agent.pl", "-server={}".format(fmc), "-level=0","-plugininfo=csvin.txt", "csv" ])
