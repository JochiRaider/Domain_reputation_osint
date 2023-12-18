import requests
import json
import urllib
import csv
import datetime

class IPQS():
    def __init__(self,key,url) -> None:
        self.key = key
        self.url = url
        self.fieldnames = ["domain","status_code","unsafe","risk_score","ip_address","server","content_type","domain_rank","dns_valid","parking","spamming","malware","phishing","suspicious","adult","redirected","category","age"]
    def IpQS_url_request(self, domain:str):
        result = {}
        url = self.url + f'{self.key}/{urllib.parse.quote_plus(domain)}'
        params = {'strictness':0,'fast':False,'timeout':5}
        response = requests.get(url,params = params)
        raw_result = json.loads(response.text)
        
        for name in self.fieldnames:
            if name == 'age':
                result["age"] = raw_result["domain_age"]["iso"]
            else:
                result[name] = raw_result.setdefault(name,'')
        return result
    
    def csv_writer(self,data:list[dict]):
        date = datetime.datetime.now()
        filename = f"{date.strftime(r'%B')}_{date.strftime(r'%d')}_{date.strftime(r'%H')}_ipqs.csv"
        with open(filename,'w',newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=self.fieldnames, restval='')
            writer.writeheader()
            writer.writerows(data)
