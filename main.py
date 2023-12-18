import virustotal 
import googleSB
import IPQS
import json

with open('api_config.txt','r') as f:
    config = json.loads(f.read())

VT_URL = config['virustotal']['url_url']
VT_KEY = config['virustotal']['key']

GSB_URL = config['googlesafebrowser']['url']
GSB_KEY = config['googlesafebrowser']['key']
GSB_ID  = config['googlesafebrowser']['ID']

IPQS_URL = config['ipqualityscore']['url']
IPQS_KEY = config['ipqualityscore']['key']

def main():
    with open('test_domains.txt','r') as q:
        domains = q.readlines()
    
    domains = [x.replace('\n','').replace('[.]','.') for x in domains]
    
    vt = virustotal.VirusTotal(VT_KEY,VT_URL)
    ipqs = IPQS.IPQS(IPQS_KEY,IPQS_URL) 
    gsb = googleSB.GoogleSafeBrowsing(GSB_KEY,GSB_URL,GSB_ID)

    results_vt = []
    results_ipqs = []
    results_gsb = []

    for domain in domains:
        results_vt.append(vt.virustotal_url_request(domain))
        results_ipqs.append(ipqs.IpQS_url_request(domain))

    results_gsb = gsb.SafeBrowsing_request(domains)

    ipqs.csv_writer(results_ipqs)
    gsb.csv_writer(results_gsb)
    vt.csv_writer(results_vt)

if __name__=='__main__':
    main()
