import requests
import json
import base64
import datetime


class VirusTotal:
    def __init__(self,key,url_url) -> None:
        self.url_url=url_url
        self.api_key=key

    def virustotal_url_request(self, domain:str)->dict:
        target = domain.encode('ascii')
        url = self.url_url + str(base64.b64encode(target).decode('ascii')).replace('=','')
        headers = {"accept": "application/json","x-apikey": self.api_key}
        response = requests.get(url, headers=headers)
        if response.ok:
            result = json.loads(response.text)
            result['data']['attributes']['categories'].setdefault('Forcepoint ThreatSeeker','')
            result['data']['attributes']['categories'].setdefault('Sophos','')
            result['data']['attributes']['categories'].setdefault('Xcitium Verdict Cloud','')
            not_good_hits = result['data']['attributes']['last_analysis_stats']['malicious'] + result['data']['attributes']['last_analysis_stats']['suspicious']
            not_seen_hits = result['data']['attributes']['last_analysis_stats']['undetected'] + result['data']['attributes']['last_analysis_stats']['timeout']
            data = {
                    'url':domain,
                    'times_submitted_vt':result['data']['attributes']['times_submitted'],
                    'response_vt':'Found',
                    'neutral_vt':result['data']['attributes']['last_analysis_stats']['harmless'],
                    'bad_vt':not_good_hits,
                    'not_seen_vt':not_seen_hits,
                    'Forcepoint ThreatSeeker':result['data']['attributes']['categories']['Forcepoint ThreatSeeker'],
                    'Sophos':result['data']['attributes']['categories']['Sophos'],
                    'Xcitium Verdict Cloud':result['data']['attributes']['categories']['Xcitium Verdict Cloud']
                    }
            try:
                crowdsourced_context = result['data']['attributes']['crowdsourced_context'][0]
                timestamp = crowdsourced_context['timestamp']
                timestamp = datetime.datetime.fromtimestamp(timestamp)
                title = result['data']['attributes']['crowdsourced_context'][0]['source'] + ' , ' + result['data']['attributes']['crowdsourced_context'][0]['title']
                data['title_vt_cs'] = title
                data['timestamp_vt_cs'] = timestamp.strftime("%B %d, %Y, %I:%M %p")
                data['details_vt_cs'] = result['data']['attributes']['crowdsourced_context'][0]['details']
                data['severity_vt_cs'] = result['data']['attributes']['crowdsourced_context'][0]['severity']
            except:
                pass
        else:
            data = {
                    'url':domain,
                    'response_vt':'Not Found'
                    }
        return data
    

def main():
    pass

if __name__=='__main__':
    main()
