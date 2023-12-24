import csv

class DataPresentation():
    def __init__(self,fieldnames:list[str],filename:str,data:list[dict]) -> None:
        self.fieldnames=fieldnames
        self.filename=filename
        self.data = data

    def csv_writer(self):
        with open(self.filename,'w',newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=self.fieldnames, restval='')
            writer.writeheader()
            writer.writerows(self.data)

def main():
    pass

if __name__=='__main__':
    main()
