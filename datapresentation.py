import csv
import datetime
import openpyxl



class DataPresentation():
    def __init__(self,fieldnames:list[str],filename:str,data:list[dict]) -> None:
        self.fieldnames=fieldnames
        self.filename=filename
        self.data = data

    def csv_writer(self):
        with open(self.filename + '.csv','w',newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=self.fieldnames, restval='',extrasaction='ignore')
            writer.writeheader()
            writer.writerows(self.data)

    def xlsx_convert(self):
        
        with open(self.filename+'.csv', 'r') as csvfile:
            reader = csv.reader(csvfile)
            data = list(reader)
        
        workbook = openpyxl.Workbook()
        worksheet = workbook.active
        for row in data:
            worksheet.append(row)
        
        workbook.save(self.filename + '.xlsx')
    
    def html_report_gen(self):
        padding_style = 'padding: 3px;'
        border_style = 'border: 1px solid;'
        collapse_style ='border-collapse: collapse;'
        true_style = 'background-color:green;color:white;'
        false_style = 'background-color:red;color:white;'
        
        table_style = f'style="{padding_style + border_style + collapse_style}"'
        table_style_g = f'style="{padding_style + border_style + collapse_style + true_style}"'
        table_style_r = f'style="{padding_style + border_style + collapse_style + false_style}"'
        table_footer = f'</table>'
        
        info_table_header = f'<table><tr><th {table_style}>URL</th><th {table_style}>IP Address</th><th {table_style}>Server Type</th><th {table_style}>Domain</th><th {table_style}>Valid DNS</th><th {table_style}>Domain Rank</th><th {table_style}>Content Type</th><th {table_style}>Status Code</th><th {table_style}>URL haus status</th><th {table_style}>VT response</th><th {table_style}>Forcepoint ThreatSeeker</th><th {table_style}>Sophos</th><th {table_style}>IP QS category</th></tr>'
        
        safety_table_header = f'<table><tr><th {table_style}>URL</th><th {table_style}>Risk Score IP QS</th><th {table_style}>Mal/Sus VT hits</th><th {table_style}>Unsafe IP QS</th><th {table_style}>Google Safe Browsing hit</th><th {table_style}>parking_ipqs</th><th {table_style}>spamming_ipqs</th><th {table_style}>malware_ipqs</th><th {table_style}>phishing_ipqs</th><th {table_style}>suspicious_ipqs</th><th {table_style}>adult_ipqs</th><th {table_style}>redirected_ipqs</th></tr>'
        
        uhaus_table_header = f'<table><tr><th {table_style}>URL</th><th {table_style}>threat_uh</th><th {table_style}>tags_uh</th><th {table_style}>date_added_uh</th><th {table_style}>spamhaus_dbl</th><th {table_style}>surbl</th></tr>'
        
        vt_cs_table_header = f'<table><tr><th {table_style}>URL</th><th {table_style}>severity_vt_cs</th><th {table_style}>timestamp_vt_cs</th><th {table_style}>title_vt_cs</th><th {table_style}>details_vt_cs</th></tr>'

        gsb_table_header = f'<table><tr><th {table_style}>URL</th><th {table_style}>platforms</th><th {table_style}>threats</th><th {table_style}>cache</th></tr>'

        safety_table_body = ''
        info_table_body = ''
        uhaus_table_body = ''
        vt_cs_table_body = ''
        gsb_table_body = ''

        info_table = ''
        safety_table = ''
        uhaus_table = ''
        vt_cs_table = ''
        gsb_table = ''

        for item in self.data:
            parking_ipqs = ''
            spamming_ipqs = ''
            malware_ipqs = ''
            phishing_ipqs = ''
            suspicious_ipqs = ''
            adult_ipqs = ''
            unsafe_ipqs = ''
            
            uhaus = item.setdefault('date_added_uh','')
            vt_cs = item.setdefault('severity_vt_cs','')
            

            if item["dns_valid_ipqs"]:  dns_valid = f'<td {table_style_g}>True</td>'
            else:  dns_valid = f'<td {table_style_r}>False</td>'
            
            if item["parking_ipqs"]:  parking_ipqs = f'<td {table_style_r}>True</td>'
            else:  parking_ipqs = f'<td {table_style_g}>False</td>'

            if item["spamming_ipqs"]:  spamming_ipqs = f'<td {table_style_r}>True</td>'
            else:  spamming_ipqs = f'<td {table_style_g}>False</td>'

            if item["malware_ipqs"]:  malware_ipqs = f'<td {table_style_r}>True</td>'
            else:  malware_ipqs = f'<td {table_style_g}>False</td>'

            if item["phishing_ipqs"]:  phishing_ipqs = f'<td {table_style_r}>True</td>'
            else:  phishing_ipqs = f'<td {table_style_g}>False</td>'

            if item["suspicious_ipqs"]:  suspicious_ipqs = f'<td {table_style_r}>True</td>'
            else:  suspicious_ipqs = f'<td {table_style_g}>False</td>'
            
            if item["adult_ipqs"]:  adult_ipqs = f'<td {table_style_r}>True</td>'
            else:  adult_ipqs = f'<td {table_style_g}>False</td>'

            if item["redirected_ipqs"]:  redirected_ipqs = f'<td {table_style_r}>True</td>'
            else:  redirected_ipqs = f'<td {table_style_g}>False</td>'

            if item["unsafe_ipqs"]:  unsafe_ipqs = f'<td {table_style_r}>True</td>'
            else:  unsafe_ipqs = f'<td {table_style_g}>False</td>'

            if item["safe_browsing_hit"]:  safe_browsing_hit = f'<td {table_style_r}>True</td>'
            else:  safe_browsing_hit = f'<td {table_style_g}>False</td>'
            
            if uhaus:
                uhaus_table_body += f'<tr><td {table_style}>{item["url"].replace(".","[.]")}</td><td {table_style}>{item["threat_uh"]}</td><td {table_style}>{item["tags_uh"]}</td><td {table_style}>{item["date_added_uh"]}</td><td {table_style}>{item["spamhaus_dbl"]}</td><td {table_style}>{item["surbl"]}</td></tr>'
            
            if vt_cs:
                vt_cs_table_body += f'<tr><td {table_style}>{item["url"].replace(".","[.]")}</td><td {table_style}>{item["severity_vt_cs"]}</td><td {table_style}>{item["timestamp_vt_cs"]}</td><td {table_style}>{item["title_vt_cs"]}</td><td {table_style}>{item["details_vt_cs"]}</td></tr>'

            if item['safe_browsing_hit']:
                gsb_table_body += f'<tr><td {table_style}>{item["url"].replace(".","[.]")}</td><td {table_style}>{item["platforms_gsb"]}</td><td {table_style}>{item["threats_gsb"]}</td><td {table_style}>{item["cache_gsb"]}</td></tr>'
            
            info_table_body += f'<tr><td {table_style}>{item["url"].replace(".","[.]")}</td><td {table_style}>{item["ip_address_ipqs"]}</td><td {table_style}>{item["server_ipqs"]}</td><td {table_style}>{item["domain_ipqs"]}</td>{dns_valid}<td {table_style}>{item["domain_rank_ipqs"]}</td><td {table_style}>{item["content_type_ipqs"]}</td><td {table_style}>{item["status_code_ipqs"]}</td><td {table_style}>{item["url_status_uh"]}</td><td {table_style}>{item["response_vt"]}</td><td {table_style}>{item.setdefault("Forcepoint ThreatSeeker","N/A")}</td><td {table_style}>{item.setdefault("Sophos","N/A")}</td><td {table_style}>{item["category_ipqs"]}</td></tr>'

            safety_table_body += f'<tr><td {table_style}>{item["url"].replace(".","[.]")}</td><td {table_style}>{item["risk_score_ipqs"]}</td><td {table_style}>{item.setdefault("bad_vt","N/A")}</td>{unsafe_ipqs}{safe_browsing_hit}{parking_ipqs}{spamming_ipqs}{malware_ipqs}{phishing_ipqs}{suspicious_ipqs}{adult_ipqs}{redirected_ipqs}</tr>'

        if uhaus_table_body:
            uhaus_table = uhaus_table_header+uhaus_table_body+table_footer

        if vt_cs_table_body:
            vt_cs_table = vt_cs_table_header+vt_cs_table_body+table_footer

        if gsb_table_body:
            gsb_table = gsb_table_header+gsb_table_body+table_footer


        info_table = info_table_header+info_table_body+table_footer
        safety_table = safety_table_header+safety_table_body+table_footer
        head = '<!DOCTYPE html><html><head></head><body>'
        foot = '</body></html>'

        body = ''

        if uhaus_table:
            body += uhaus_table

        if vt_cs_table:
            body += vt_cs_table

        if gsb_table:
            body += gsb_table

        body += info_table + safety_table

        with open(self.filename + '.html','w',newline='') as g:
            g.write(head + body + foot)


def main():
    pass

if __name__=='__main__':
    main()
