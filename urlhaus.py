import urllib3
import json

class URLHaus():
    def __init__(self) -> None:
        pass

    def query_urlhaus(self,url):
        pool = urllib3.HTTPSConnectionPool('urlhaus-api.abuse.ch', port=443, maxsize=10)
        data = {'url' : url}
        response = pool.request_encode_body('POST', '/v1/url/', fields=data, encode_multipart=False)
        
        response = response.data.decode('utf-8', 'ignore')
        
        json_response = json.loads(response)
        if json_response['query_status'] == 'ok':
            results = {
                'url': url,
                'url_status_uh': json_response['url_status'],
                'threat_uh': json_response['threat'],
                'date_added_uh': json_response['date_added'],
                'tags_uh': json_response['tags'],
                'spamhaus_dbl':json_response['blacklists']['spamhaus_dbl'],
                'surbl':json_response['blacklists']['surbl']
            }
        else:
            results = {
                'url': url,
                'url_status_uh':'no_results'
            }
        return results
        

def main():
    pass
    
if __name__=='__main__':
    main()
