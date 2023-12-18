import virustotal 
import googleSB
import json

with open('test_domains.txt','r') as q:
    domains = q.readlines()
    
domains = [x.replace('\n','').replace('[.]','.') for x in domains]

with open('api_config.txt','r') as f:
    config = json.loads(f.read())

VT_URL = config['virustotal']['url_url']
VT_KEY = config['virustotal']['key']

GSB_URL = config['googlesafebrowser']['url']
GSB_KEY = config['googlesafebrowser']['key']
GSB_ID  = config['googlesafebrowser']['ID']

vt = virustotal.VirusTotal(VT_KEY,VT_URL)
results_vt = []
for domain in domains:
    results_vt.append(vt.virustotal_url_request(domain))

vt.csv_writer(results_vt)

results_gsb = []

gsb = googleSB.GoogleSafeBrowsing(GSB_KEY,GSB_URL,GSB_ID)
results_gsb = gsb.SafeBrowsing_request(domains)

gsb.csv_writer(results_gsb)

