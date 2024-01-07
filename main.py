import virustotal 
import googleSB
import ipqualityscore
import urlhaus
import datapresentation
import datetime
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
    date = datetime.datetime.now()
    fieldnames = ['url','ip_address_ipqs','server_ipqs','domain_ipqs','dns_valid_ipqs','unsafe_ipqs','severity_vt_cs','safe_browsing_hit','response_vt','status_code_ipqs','url_status_uh','Forcepoint ThreatSeeker','Sophos','spamhaus_dbl','surbl','category_ipqs','risk_score_ipqs','domain_rank_ipqs','neutral_vt','bad_vt','not_seen_vt','times_submitted_vt','date_added_uh','threat_uh','tags_uh','age_ipqs','parking_ipqs','spamming_ipqs','malware_ipqs','phishing_ipqs','suspicious_ipqs','adult_ipqs','redirected_ipqs','content_type_ipqs','platforms_gsb','threats_gsb','cache_gsb','title_vt_cs','timestamp_vt_cs','details_vt_cs']
    filename = f"{date.strftime(r'%B')}_{date.strftime(r'%d')}_{date.strftime(r'%H')}_{date.strftime(r'%M')}_results"
    results_list = []

    with open('test_domains.txt','r') as q:
        domains = q.readlines()
        domains = [x.replace('\n','').replace('[.]','.') for x in domains]
    
    with open('email_parts.txt','r') as f:
        email_parts = json.loads(f.read())


    vt = virustotal.VirusTotal(VT_KEY,VT_URL)
    ipqs = ipqualityscore.IPQS(IPQS_KEY,IPQS_URL) 
    gsb = googleSB.GoogleSafeBrowsing(GSB_KEY,GSB_URL,GSB_ID)
    uhaus = urlhaus.URLHaus()
        
    gsb_r = gsb.SafeBrowsing_request(domains)
    for domain in domains:
        vt_r = vt.virustotal_url_request(domain) 
        uhaus_r = uhaus.query_urlhaus(domain)
        ipqs_r = ipqs.IpQS_url_request(domain)
        gsb_r_d = gsb_r[domain]
        
        results_list.append(vt_r | uhaus_r | ipqs_r | gsb_r_d)
        
    dp = datapresentation.DataPresentation(fieldnames,filename,results_list) 
    dp.csv_writer()
    dp.html_report_gen(email_parts['header'],email_parts['footer'])

if __name__=='__main__':
    main()
