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

    def get_description(self):
        descriptions = self.containers["cna"]["descriptions"]
        for description in descriptions:
            value = description["value"]
        return value

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

def is_cve_id_present(cve_id, list_matching_cve):
    for cve in list_matching_cve:
        if cve['cve_id'] == cve_id:
            return True
    return False
def sanitize_keyWords(keyWords):
    keyWords= keyWords.replace("-", " ")
    keyWords= keyWords.replace("_", " ")
    keyWords= keyWords.replace(",", " ")
    keyWords= keyWords.replace(".", " ")
    return keyWords

def calculate_average_baseScore(list_matching_cve):
    sum_baseScores=0
    for cve in list_matching_cve:
        sum_baseScores += cve['metrics']['baseScore']
    avg_base_score = sum_baseScores / len(list_matching_cve)
    return round(avg_base_score, 1)#restituisco basescore arrotondato alla prima cifra decimale
def calculate_average_attackComplexity(list_matching_cve):
    complexity_values = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}
    total_complexity = 0
    count = 0
    for cve in list_matching_cve:
        complexity = cve['metrics']['attackComplexity']
        if complexity in complexity_values:
            total_complexity += complexity_values[complexity]
            count += 1

    if count == 0:
        return 'NONE'  # Se non ci sono valori validi, la media è 'NONE'
    average_complexity = total_complexity / count
    print(f"----------->media complessità attacco:{average_complexity}")
    # Determina la stringa corrispondente alla media calcolata
    if average_complexity < 1:
        return 'LOW'
    elif average_complexity < 2:
        return 'MEDIUM'
    elif average_complexity < 3:
        return 'HIGH'

def calculate_average_confidentialityImpact(list_matching_cve):
        confidentialityImpact_values = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        total_confImpact = 0
        count = 0
        for cve in list_matching_cve:
            confidentialityImpact = cve['metrics']['confidentialityImpact']
            if confidentialityImpact in confidentialityImpact_values:
                total_confImpact += confidentialityImpact_values[confidentialityImpact]
                count += 1

        if count == 0:
            return 'NONE'  # Se non ci sono valori validi, la media è 'NONE'
        average_confidentialityImpact = total_confImpact / count
        print(f"----------->media confidentiality impact :{average_confidentialityImpact}")
        # Determina la stringa corrispondente alla media calcolata
        if average_confidentialityImpact < 1:
            return 'LOW'
        elif average_confidentialityImpact < 2:
            return 'MEDIUM'
        elif average_confidentialityImpact < 3:
            return 'HIGH'
        elif average_confidentialityImpact < 3.4:
            return 'CRITICAL'

def calculate_average_integrityImpact(list_matching_cve):
    integrityImpact_values = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
    total_intImpact = 0
    count = 0
    for cve in list_matching_cve:
        integrityImpact = cve['metrics']['integrityImpact']
        if integrityImpact in integrityImpact_values:
            total_intImpact += integrityImpact_values[integrityImpact]
            count += 1

    if count == 0:
        return 'NONE'  # Se non ci sono valori validi, la media è 'NONE'
    average_integrityImpact = total_intImpact / count
    print(f"----------->media integrity impact :{average_integrityImpact}")
    # Determina la stringa corrispondente alla media calcolata
    if average_integrityImpact < 1:
        return 'LOW'
    elif average_integrityImpact < 2:
        return 'MEDIUM'
    elif average_integrityImpact < 3:
        return 'HIGH'
    elif average_integrityImpact < 3.4:
        return 'CRITICAL'

def calculate_average_availabilityImpact(list_matching_cve):
    availabilityImpact_values = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
    total_avaImpact = 0
    count = 0
    for cve in list_matching_cve:
        availabilityImpact = cve['metrics']['availabilityImpact']
        if availabilityImpact in availabilityImpact_values:
            total_avaImpact += availabilityImpact_values[availabilityImpact]
            count += 1

    if count == 0:
        return 'NONE'  # Se non ci sono valori validi, la media è 'NONE'
    average_availabilityImpact = total_avaImpact / count
    print(f"----------->media integrity impact :{average_availabilityImpact}")
    # Determina la stringa corrispondente alla media calcolata
    if average_availabilityImpact < 1:
        return 'LOW'
    elif average_availabilityImpact < 2:
        return 'MEDIUM'
    elif average_availabilityImpact < 3:
        return 'HIGH'
    elif average_availabilityImpact < 3.4:
        return 'CRITICAL'

def calculate_average_privilegesRequired(list_matching_cve):
    privilegesRequired_values = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}
    average_privilegesRequired = 0
    count = 0
    for cve in list_matching_cve:
        privilegesRequired = cve['metrics']['privilegesRequired']
        if privilegesRequired in privilegesRequired_values:
            average_privilegesRequired += privilegesRequired_values[privilegesRequired]
            count += 1

    if count == 0:
        return 'NONE'  # Se non ci sono valori validi, la media è 'NONE'
    average_privilegesRequired = average_privilegesRequired / count
    print(f"----------->media privilegesRequired :{average_privilegesRequired}")
    # Determina la stringa corrispondente alla media calcolata
    if average_privilegesRequired < 1:
        return 'LOW'
    elif average_privilegesRequired < 2:
        return 'MEDIUM'
    elif average_privilegesRequired < 3:
        return 'HIGH'
    elif average_privilegesRequired < 3.4:
        return 'CRITICAL'
def calculate_average_baseSeverity(list_matching_cve):
    severity_values = {'NONE': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
    total_severity = 0
    count = 0
    for cve in list_matching_cve:
        severity = cve['metrics']['baseSeverity']
        if severity in severity_values:
            total_severity  += severity_values[severity]
            count += 1

    if count == 0:
        return 'NONE'  # Se non ci sono valori validi, la media è 'NONE'
    average_severity= total_severity / count
    print(f"----------->media base severity:{average_severity}")
    # Determina la stringa corrispondente alla media calcolata
    if average_severity< 1:
        return 'LOW'
    elif average_severity < 2:
        return 'MEDIUM'
    elif average_severity < 3:
        return 'HIGH'
    elif average_severity < 3.4:
        return 'CRITICAL'


def get_risk(techniqueKeyWord):
    n_cves=0
    n_cves_with_metrics_and_match=0
    techniqueKeyWord = sanitize_keyWords(techniqueKeyWord)  # elaboro le keyword e tolgo eventuali caratteri problematici

    print(f"--> RETRIVING INFORMATION OF All CVEs FROM dir  <--\n")
    list_all_cves_datas= get_list_of_CVEs_from_dir(r"C:\Users\franc\Desktop\mitrepy\mitreattack-python\fkg_cs\json_CVE")#ottengo lista con i dati di TUTTI i cve presenti nella cartella json
    list_cves_matching_keyword = []  # lista delle cve con relative metriche che hanno corrispondenza con parole chiave


    for cve_data in list_all_cves_datas:
        n_cves+=1
        #itero su tutti i file json convertiti in lista di cve_data e controllo quali hanno tutte le metriche che mi servono
        if cve_data.has_metrics():#solo se ha le metriche che mi servono controllo la descrizione
           cve_data_description = cve_data.get_description()

           for word in techniqueKeyWord.split():
               # controllo se la descrizione della cve ha le parole chiave della tecnica
               if len(word) >= 4 and ( word in cve_data_description or word.lower() in cve_data_description or word.upper() in cve_data_description) or ( techniqueKeyWord.lower() in cve_data_description or techniqueKeyWord.upper() in cve_data_description ):
                   cve_matching_keyword=dict()#dizionario contenente informazioni su singolo cve con corrispondenze su parole chiave
                   #stampe a video per CL
                   print(f"--> CVE ID with metrics and keywords ('{techniqueKeyWord}')->('{word}')  in description: {cve_data.get_cveId()} ")
                   print(f"--> CVE description: {cve_data.get_description()}")
                   print(f"--> CVE METRICS: ")
                   print(f"                BASE SCORE: [{cve_data.get_cvss_baseScore()}] ")
                   print(f"                ATTACK COMPLEXITY: {cve_data.get_cvss_attackComplexity()} ")
                   print(f"                ATTACK BASE SEVERITY: {cve_data.get_cvss_baseSeverity()} ")
                   print(f"                ATTACK CONFIDENTIALITY IMPACT: {cve_data.get_cvss_confidentialityImpact()} ")
                   print(f"                ATTACK INTEGRITY IMPACT: {cve_data.get_cvss_integrityImpact()} ")
                   print(f"                ATTACK AVAILABILITY IMPACT: {cve_data.get_cvss_availabilityImpact()} ")
                   print(f"                PRIVILEGES REQUIRED: {cve_data.get_cvss_privilegesRequired()} ")
                   print("-------------------------------------------------------------------------------")

                   #popolo metriche che mi servono
                   cve_metrics = dict()
                   cve_metrics['baseScore']=cve_data.get_cvss_baseScore()
                   cve_metrics['attackComplexity'] = cve_data.get_cvss_attackComplexity()
                   cve_metrics['baseSeverity'] = cve_data.get_cvss_baseSeverity()
                   cve_metrics['confidentialityImpact'] = cve_data.get_cvss_confidentialityImpact()
                   cve_metrics['integrityImpact'] = cve_data.get_cvss_integrityImpact()
                   cve_metrics['availabilityImpact'] = cve_data.get_cvss_availabilityImpact()
                   cve_metrics['privilegesRequired'] = cve_data.get_cvss_privilegesRequired()
                   #creo oggetto da inserire nella lista
                   cve_matching_keyword['cve_id'] = cve_data.get_cveId()
                   cve_matching_keyword['metrics'] = cve_metrics
                   #aggiungo oggetto alla lista solo se il cve_id non è già presente nella lista dei match
                   if not is_cve_id_present(cve_data.get_cveId(), list_cves_matching_keyword): #faccio append solo se non l'ho gia trovato
                     n_cves_with_metrics_and_match += 1
                     list_cves_matching_keyword.append(cve_matching_keyword)

    print(f"---REPORT:number of CVEs with required metrics:{n_cves_with_metrics_and_match} out of {n_cves} CVEs---")
    #print(f"---REPORT: list of matching CVEs:{list_cves_matching_keyword}")#stampa debug
    print(f"---REPORT: media dei basescores: {calculate_average_baseScore(list_cves_matching_keyword)}")
    print(f"---REPORT: media dei attack complexity: {calculate_average_attackComplexity(list_cves_matching_keyword)}")
    print(f"---REPORT: media delle base severity: {calculate_average_baseSeverity(list_cves_matching_keyword)}")
    print(f"---REPORT: media delle confidentiality impact: {calculate_average_confidentialityImpact(list_cves_matching_keyword)}")
    print(f"---REPORT: media delle integrity impact: {calculate_average_integrityImpact(list_cves_matching_keyword)}")
    print(f"---REPORT: media delle avalabilityty impact: {calculate_average_availabilityImpact(list_cves_matching_keyword)}")
    print(f"---REPORT: media dei previlegi: {calculate_average_privilegesRequired(list_cves_matching_keyword)}")

if __name__ == "__main__":
    get_risk("cross-site scripting (XSS)")
