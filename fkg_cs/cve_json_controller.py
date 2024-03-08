import json
import os
import pprint


class CveData:
    def __init__(self, json_file):
        with open(json_file , encoding="utf-8") as f:
            data = json.load(f)
            self.dataType = data.get('dataType')
            self.dataVersion = data.get('dataVersion')
            self.cveMetadata = data.get('cveMetadata')
            self.containers = data.get('containers')

    def get_dataType(self):
        return self.dataType

    def get_dataVersion(self):
        return self.dataVersion

    def get_cveMetadata(self):
        return self.cveMetadata

    def get_containers(self):
        return self.containers

    #methods used to read cve metatadata
    def get_cveId(self):
        return self.cveMetadata.get('cveId')

    def get_assignerOrgId(self):
        return self.cveMetadata.get('assignerOrgId')

    def get_state(self):
        return self.cveMetadata.get('state')

    def get_assignerShortName(self):
        return self.cveMetadata.get('assignerShortName')

    def get_dateReserved(self):
        return self.cveMetadata.get('dateReserved')

    def get_datePublished(self):
        return self.cveMetadata.get('datePublished')

    def get_dateUpdated(self):
        return self.cveMetadata.get('dateUpdated')

    def get_cna(self):
        return self.containers["cna"]
    def has_cna(self):
        if not self.get_cna():
            return False
        else:
            return True
    def get_metrics(self):
        cvssV3_1=dict()
        for metric in self.get_cna()["metrics"]:
            if "cvssV3_1" in metric:
                # Se l'oggetto contiene cvssV3_1
                cvssV3_1 = metric["cvssV3_1"]
        return cvssV3_1

    def has_metrics(self):
        if self.has_cna():
            if 'metrics' in self.get_cna():
                cvss_metrics = self.get_metrics()
                #print("CVSS metrics:", cvss_metrics)#debug metriche lette
                if 'baseScore' in cvss_metrics and 'baseSeverity' in cvss_metrics and 'attackComplexity' in cvss_metrics and 'confidentialityImpact' in cvss_metrics and 'integrityImpact' in cvss_metrics and 'availabilityImpact' in cvss_metrics and 'privilegesRequired' in cvss_metrics:
                    return True
                else:
                    return False
            else:
                return False
        else:
            return False
    #methods used to access metrics details
    def get_cvss_attackComplexity(self):
        cvss_metrics = self.get_metrics()#essendo una lista devo perforza dare primo indice
        return cvss_metrics['attackComplexity']
    def has_cvss_attackComplexity(self):
        cvss_metrics = self.get_metrics()
        if 'attackComplexity' in cvss_metrics['cvssV3_1']:
            return True
        else:
            return False

    def get_cvss_attackVector(self):
        cvss_metrics = self.get_metrics()
        return cvss_metrics['cvssV3_1']['attackVector']
    def has_cvss_attackVector(self):
        cvss_metrics = self.get_metrics()
        if 'attackVector' in cvss_metrics['cvssV3_1']:
            return True
        else:
            return False
    def get_cvss_availabilityImpact(self):
        cvss_metrics = self.get_metrics()
        return cvss_metrics['availabilityImpact']
    def get_cvss_baseScore(self):
        cvss_metrics = self.get_metrics()
        return cvss_metrics['baseScore']
    def get_cvss_baseSeverity(self):
        cvss_metrics = self.get_metrics()
        return cvss_metrics['baseSeverity']
    def get_cvss_confidentialityImpact(self):
        cvss_metrics = self.get_metrics()
        return cvss_metrics['confidentialityImpact']
    def get_cvss_integrityImpact(self):
        cvss_metrics = self.get_metrics()
        return cvss_metrics['integrityImpact']
    def get_cvss_privilegesRequired(self):
        cvss_metrics = self.get_metrics()
        return cvss_metrics['privilegesRequired']
    def get_cvss_scope(self):
        cvss_metrics = self.get_metrics()
        return cvss_metrics['scope']
    def get_cvss_userInteraction(self):
        cvss_metrics = self.get_metrics()
        return cvss_metrics['userInteraction']
    def get_cvss_vectorString(self):
        cvss_metrics = self.get_metrics()
        return cvss_metrics['vectorString']
    def get_cvss_version(self):
        cvss_metrics = self.get_metrics()
        return cvss_metrics['version']

def get_list_of_CVEs_from_dir(root_path):
    list_cves_datas = []
    # Attraversa tutte le cartelle e aggiunge a cve data list
    if not os.path.exists(root_path):
        print(f"La directory {root_path} dell'arichio CVE json non esiste.")
    else:
      for dirpath, dirnames, filenames in os.walk(root_path):
         for filename in filenames:
           file_path = os.path.join(dirpath, filename)
           #print(f"Sto recuperando i file di {file_path}")
           cve_data=CveData(file_path)
           #print(f"CVE DATA LETTO: {cve_data}")
           list_cves_datas.append(cve_data)

    #print("returno Lista dati cve:")
    #pprint.pprint(list_cves_datas)
    return list_cves_datas
def get_risk(technique_id):
    n_cves_with_metrics=0
    list_cves_datas=[]
    print(f"--> RETRIVING INFORMATION OF All CVEs FROM dir  <--\n")
    list_cves_datas= get_list_of_CVEs_from_dir(r"C:\Users\franc\Desktop\mitrepy\mitreattack-python\fkg_cs\json_CVE")

    for cve_data in list_cves_datas:
        #itero su tutti i file json convertiti in lista di cve_data e controllo quali hanno tutte le metriche che mi servono
        if cve_data.has_metrics():
           n_cves_with_metrics+=1
           print(f"--> CVE ID with metrics: {cve_data.get_cveId()} ")
           #print(f"--> PUBLISHING DATE: {cve_data.get_datePublished()}")
           print(f"--> CVE METRICS: ")
        #  pprint.pprint(cve_json_data.get_metrics())#STAMPA DEBUG
           print(f"                BASE SCORE: [{cve_data.get_cvss_baseScore()}] ")
           print(f"                ATTACK COMPLEXITY: {cve_data.get_cvss_attackComplexity()} ")
           print(f"                ATTACK BASE SEVERITY: {cve_data.get_cvss_baseSeverity()} ")
           print(f"                ATTACK AVAILABILITY IMPACT: {cve_data.get_cvss_availabilityImpact()} ")
           print(f"                ATTACK CONFIDENTIALITY IMPACT: {cve_data.get_cvss_confidentialityImpact()} ")
           print(f"                ATTACK INTEGRITY IMPACT: {cve_data.get_cvss_integrityImpact()} ")
           print(f"                PRIVILEGES REQUIRED: {cve_data.get_cvss_privilegesRequired()} ")
    print(f"---REPORT:totale cve con metriche necessarie:{n_cves_with_metrics}---")


if __name__ == "__main__":
    get_risk("T1133")
