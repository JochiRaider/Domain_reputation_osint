import requests
import json
import base64
import csv
import datetime

with open('api_config.txt','r') as f:
    config = json.loads(f.read())

URL = config['virustotal']['url']
KEY = config['virustotal']['key']

class VirusTotal:
    def __init__(self) -> None:
        self.url_url=URL
        self.api_key=KEY

    def virustotal_url_request(self, domain:str)->dict:
        target = domain.encode('ascii')
        url = self.url_url + str(base64.b64encode(target).decode('ascii')).replace('=','')
        headers = {"accept": "application/json","x-apikey": self.api_key}
        response = requests.get(url, headers=headers)
        if response.ok:
            result = json.loads(response.text)
            result['data']['attributes']['categories'].setdefault('Forcepoint ThreatSeeker','')
            result['data']['attributes']['categories'].setdefault('Sophos','')
            result['data']['attributes']['categories'].setdefault('BitDefender','')
            result['data']['attributes']['categories'].setdefault('Xcitium Verdict Cloud','')
            data = {
                    'domain':domain,
                    'times_submitted':result['data']['attributes']['times_submitted'],
                    'response': '200',
                    'reputation':result['data']['attributes']['reputation'],
                    'harmless':result['data']['attributes']['last_analysis_stats']['harmless'],
                    'malicious':result['data']['attributes']['last_analysis_stats']['malicious'],
                    'suspicious':result['data']['attributes']['last_analysis_stats']['suspicious'],
                    'undetected':result['data']['attributes']['last_analysis_stats']['undetected'],
                    'timeout':result['data']['attributes']['last_analysis_stats']['timeout'],
                    'Forcepoint ThreatSeeker':result['data']['attributes']['categories']['Forcepoint ThreatSeeker'],
                    'Sophos':result['data']['attributes']['categories']['Sophos'],
                    'BitDefender':result['data']['attributes']['categories']['BitDefender'],
                    'Xcitium Verdict Cloud':result['data']['attributes']['categories']['Xcitium Verdict Cloud']
                    }
        else:
            data = {
                    'domain':domain,
                    'response':'404'
                    }
        return data
    
    def csv_writer(self,data:dict):
        fieldnames = ['domain','response','reputation','harmless','malicious','suspicious','undetected','timeout','times_submitted','Forcepoint ThreatSeeker','Sophos','BitDefender','Xcitium Verdict Cloud']
        date = datetime.datetime.now()
        filename = f"{date.strftime(r'%B')}_{date.strftime(r'%d')}_{date.strftime(r'%H')}_virustotal.csv"
        with open(filename,'w',newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, restval='')
            writer.writeheader()
            writer.writerows(data)


def main():
    pass

if __name__=='__main__':
    main()