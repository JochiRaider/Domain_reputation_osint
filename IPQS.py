import requests
import json
import urllib

class IPQS():
    def __init__(self,key,url) -> None:
        self.key = key
        self.url = url
        self.fieldnames = ["status_code","unsafe","risk_score","ip_address","server","content_type","domain_rank","dns_valid","parking","spamming","malware","phishing","suspicious","adult","redirected","category","age"]
    def IpQS_url_request(self, domain:str):
        result = {'url':domain}
        url = self.url + f'{self.key}/{urllib.parse.quote_plus(domain)}'
        params = {'strictness':0,'fast':False,'timeout':5}
        response = requests.get(url,params = params)
        raw_result = json.loads(response.text)
        
        for name in self.fieldnames:
            if name == 'age':
                result["age_ipqs"] = raw_result["domain_age"]["iso"]
            else:
                result[name+'_ipqs'] = raw_result.setdefault(name,'')
        return result
    

