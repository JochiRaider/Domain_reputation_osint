import requests
import json

class GoogleSafeBrowsing():
    def __init__(self,key:str,url:str,id:str) -> None:
        self.key = key
        self.url = url
        self.id = id

    def SafeBrowsing_request(self, domains:list[str])->dict[str:dict]:
        payload = {
            "client":{
                "clientId": self.id, 
                "clientVersion": '0.1.3'},
            "threatInfo":{
                "threatTypes":[
                    "THREAT_TYPE_UNSPECIFIED",
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
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
                                'url': domain,
                                'safe_browsing_hit': True,
                                'platforms_gsb': ','.join(list(set([b['platformType'] for b in matches]))),
                                'threats_gsb': ','.join(list(set([b['threatType'] for b in matches]))),
                                'cache_gsb': min([b["cacheDuration"] for b in matches])
                            })
                        else:
                            results.append({
                                'url': domain,
                                'safe_browsing_hit': False
                            })  
            else:
                for domain in domains:
                    results.append({
                        'url': domain,
                        'safe_browsing_hit': False
                        })
                return {result['url']: result for result in results}
        else:
            for domain in domains:
                results.append({
                    'url': domain,
                    'safe_browsing_hit': False
                    })
            return {result['url']: result for result in results}
        return {result['url']: result for result in results}
    

def main():
    pass
