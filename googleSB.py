import requests
import json
import csv
import datetime

class GoogleSafeBrowsing():
    def __init__(self,key:str,url:str,id:str) -> None:
        self.key = key
        self.url = url
        self.id = id

    def SafeBrowsing_request(self, domains:list[str]):
        payload = {
            "client":{
                "clientId": self.id, 
                "clientVersion": '0.1.3'},
            "threatInfo":{
                "threatTypes":[
                    "THREAT_TYPE_UNSPECIFIED",
                    "MALWARE","SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes":["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries":[{'url':domain} for domain in domains]}}
        
        headers = {'Content-type': 'application/json'}
        response = requests.post(self.url,data=json.dumps(payload),params={'key':self.key},headers=headers)
        results = []
        if response.ok:
            if response.json():
                for domain in domains:
                        matches = [match for match in response.json()['matches'] if match['threat']['url'] == domain]
                        if matches: 
                            results.append({
                                'domain': domain,
                                'malicious': True,
                                'platforms': ','.join(list(set([b['platformType'] for b in matches]))),
                                'threats': ','.join(list(set([b['threatType'] for b in matches]))),
                                'cache': min([b["cacheDuration"] for b in matches])
                            })
                        else:
                            results.append({
                                'domain': domain,
                                'malicious': False
                            })  
            else:
                return None

        else:
            return None
        return results
    
    def csv_writer(self,data:list[dict]):
        fieldnames = ['domain','malicious','platforms','threats','cache']
        date = datetime.datetime.now()
        filename = f"{date.strftime(r'%B')}_{date.strftime(r'%d')}_{date.strftime(r'%H')}_google_safe_browsing.csv"
        with open(filename,'w',newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, restval='')
            writer.writeheader()
            writer.writerows(data)

def main():
    pass

if __name__=='__main__':
    main()