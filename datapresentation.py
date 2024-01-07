import csv
import datetime
import openpyxl
import json


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
    
    def create_table_header(self, columns, table_style):
        header = f'<tr>'
        for col in columns:
            header += f'<th {table_style}>{col}</th>'
        header += '</tr>'
        return header
    
    def create_table_row(self, data_row, table_styles):
        row = '<tr>'
        for data in data_row:
            row += f'<td {table_styles}>{data}</td>'
        row += '</tr>'
        return row

    def create_dynamic_table(self, columns, table_id, caption):
        padding_style = 'padding: 3px;'
        border_style = 'border: 1px solid;'
        collapse_style = 'border-collapse: collapse;'
        table_style = f'style="{padding_style + border_style + collapse_style}"'
        table_header = self.create_table_header(columns, table_style)
        table_body = ''
        for item in self.data:
            row_data = [item.get(col, 'N/A') for col in columns]
            if all(value == 'N/A' for value in row_data[1:]):
                continue            
            table_body += self.create_table_row(row_data, table_style)
        return f'<table id="{table_id}"{table_style}><caption>{caption}</caption>{table_header}{table_body}</table>'


    def html_report_gen(self,main_head,main_foot):
 
        uhaus_table_col = ["url","threat_uh","tags_uh","date_added_uh","spamhaus_dbl","surbl"]
        uhuas_cap = 'URLhaus Data'
        uhuas_id = 'uhaus_table'
        uhaus_table = self.create_dynamic_table(uhaus_table_col,uhuas_id,uhuas_cap)
    
        vt_vcs_table_col = ["url","severity_vt_cs","timestamp_vt_cs","title_vt_cs","details_vt_cs"]
        vt_vcs_table_cap = 'VT Crowd Source Data'
        vt_vcs_table_id = 'vt_vcs'       
        vt_cs_table = self.create_dynamic_table(vt_vcs_table_col,vt_vcs_table_id,vt_vcs_table_cap)
           
        info_table_col = ["url","ip_address_ipqs","server_ipqs","domain_ipqs","domain_rank_ipqs","content_type_ipqs","status_code_ipqs","url_status_uh","response_vt","bad_vt","safe_browsing_hit","unsafe_ipqs","Forcepoint ThreatSeeker","Sophos","category_ipqs"]
        info_table_cap = 'URL Information'
        info_table_id = 'info_table_id'
        info_table = self.create_dynamic_table(info_table_col,info_table_id,info_table_cap)

        safety_table_col = ["url","dns_valid_ipqs","parking_ipqs","spamming_ipqs","malware_ipqs","phishing_ipqs","suspicious_ipqs","adult_ipqs","redirected_ipqs"]
        safety_table_cap = 'IP QS categories'
        safety_table_id = 'booliens'        
        safety_table = self.create_dynamic_table(safety_table_col,safety_table_id,safety_table_cap)
        
        gsb_table_col = ["url","platforms_gsb","threats_gsb","cache_gsb"]
        gsb_table_cap = 'Google Safe Browsing Data'
        gsb_table_id = 'gsb'        
        gsb_table = self.create_dynamic_table(gsb_table_col,gsb_table_id,gsb_table_cap)

        head = main_head 
        foot = main_foot

        body = '<div align="center">' + info_table + safety_table +'</div>''<div align="center">' + uhaus_table + vt_cs_table +   gsb_table +'</div>'

        with open(self.filename + '.html','w',newline='') as g:
            g.write(head + body + foot)

def main():
    pass

if __name__=='__main__':
    main()
