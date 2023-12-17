import virustotal 

with open('test_domains.txt','r') as q:
    domains = q.readlines()
    
domains = [x.replace('\n','') for x in domains]

vt = virustotal.VirusTotal()
results = []
for domain in domains:
    results.append(vt.virustotal_url_request(domain))

vt.csv_writer(results)

