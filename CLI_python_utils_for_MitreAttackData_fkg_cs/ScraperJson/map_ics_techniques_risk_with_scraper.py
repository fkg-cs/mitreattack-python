from mitreattack.stix20.MitreAttackData import MitreAttackData
import os
import matplotlib.pyplot as plt
from Janus.model.CveData import CveData


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
           cve_data= CveData(file_path)
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
    avg_base_score=0
    for cve in list_matching_cve:
        sum_baseScores += cve['metrics']['baseScore']
    if len(list_matching_cve) != 0:
      avg_base_score = sum_baseScores / len(list_matching_cve)

    return round(avg_base_score, 2)#restituisco basescore arrotondato alla prima cifra decimale
def calculate_average_attackComplexity(list_matching_cve):
    complexity_values = {'LOW': 1, 'HIGH': 2 }
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
    else:
        return 'HIGH'

def calculate_average_confidentialityImpact(list_matching_cve):
        confidentialityImpact_values = {'NONE': 0, 'LOW': 1, 'HIGH': 2}
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
        if average_confidentialityImpact == 0:
            return 'NONE'
        elif average_confidentialityImpact < 1:
            return 'LOW'
        elif average_confidentialityImpact < 2:
            return 'HIGH'


def calculate_average_integrityImpact(list_matching_cve):
    integrityImpact_values = {'NONE': 0, 'LOW': 1, 'HIGH': 2}
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
    print(f"----------->media confidentiality impact :{average_integrityImpact}")
    # Determina la stringa corrispondente alla media calcolata
    if average_integrityImpact == 0:
        return 'NONE'
    elif average_integrityImpact < 1:
        return 'LOW'
    elif average_integrityImpact < 2:
        return 'HIGH'

def calculate_average_availabilityImpact(list_matching_cve):
    availabilityImpact_values = {'NONE': 0, 'LOW': 1, 'HIGH': 2}
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
    if average_availabilityImpact == 0:
        return 'NONE'
    elif average_availabilityImpact < 1:
        return 'LOW'
    elif average_availabilityImpact < 2:
        return 'HIGH'

def calculate_average_privilegesRequired(list_matching_cve):
    privilegesRequired_values = {'NONE': 0, 'LOW': 1, 'HIGH': 2}
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
    if average_privilegesRequired == 0:
        return 'NONE'
    elif average_privilegesRequired < 1:
        return 'LOW'
    elif average_privilegesRequired < 2:
        return 'HIGH'


#metodo principale richiamato dalla vista sulle parole chiave della tecnica
def get_technique_risk_scores(techniqueKeyWords):
    commonWords = ["the", "of", "is", "an", "and", "a", "to", "with", "not", "or", "while", "this", "that", "on",
                   "does", "do", "by", "in", "more"]
    risk_score=dict()
    n_cves=0
    n_cves_with_metrics_and_match=0
    techniqueKeyWords = sanitize_keyWords(techniqueKeyWords)  # elaboro le keyword e tolgo eventuali caratteri problematici

    print(f"--> RETRIVING INFORMATION OF All CVEs FROM dir  <--\n")
    list_all_cves_datas= get_list_of_CVEs_from_dir(r"../../Janus/json/json_CVE")#ottengo lista con i dati di TUTTI i cve presenti nella cartella json
    list_cves_matching_keyword = []  # lista delle cve con relative metriche che hanno corrispondenza con parole chiave


    for cve_data in list_all_cves_datas:
        n_cves+=1
        #itero su tutti i file json convertiti in lista di cve_data e controllo quali hanno tutte le metriche che mi servono
        if cve_data.has_metrics():#solo se ha le metriche che mi servono controllo la descrizione
           cve_data_description = cve_data.get_description()

           for word in techniqueKeyWords.split():# controllo se la descrizione della tecnica sudivisa in parole chiave ha corrispondenza con la descrizione della cve
               if word not in commonWords and (word.lower() in cve_data_description.lower().split()):
                   if not is_cve_id_present(cve_data.get_cveId(), list_cves_matching_keyword): #faccio append solo se non l'ho gia inserito nella lista
                       n_cves_with_metrics_and_match += 1
                       cve_matching_keyword=dict()#dizionario contenente informazioni su singolo cve con corrispondenze su parole chiave
                       #stampe a video per CL
                       print(f"--> CVE ID with metrics and keywords ('{techniqueKeyWords}')->('{word}')  in description: {cve_data.get_cveId()} ")
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
                       list_cves_matching_keyword.append(cve_matching_keyword)


    print(f"---REPORT:number of CVEs with required metrics:{n_cves_with_metrics_and_match} out of {n_cves} CVEs---")
    #print(f"---REPORT: list of matching CVEs:{list_cves_matching_keyword}")#stampa debug
    print(f"---REPORT: media dei basescores: {calculate_average_baseScore(list_cves_matching_keyword)}")
    print(f"---REPORT: media dei attack complexity: {calculate_average_attackComplexity(list_cves_matching_keyword)}")
    print(f"---REPORT: media delle confidentiality impact: {calculate_average_confidentialityImpact(list_cves_matching_keyword)}")
    print(f"---REPORT: media delle integrity impact: {calculate_average_integrityImpact(list_cves_matching_keyword)}")
    print(f"---REPORT: media delle avalabilityty impact: {calculate_average_availabilityImpact(list_cves_matching_keyword)}")
    print(f"---REPORT: media dei previlegi: {calculate_average_privilegesRequired(list_cves_matching_keyword)}")
    risk_score['baseScore']=calculate_average_baseScore(list_cves_matching_keyword)
    risk_score['attackComplexity'] = calculate_average_attackComplexity(list_cves_matching_keyword)
    risk_score['confidentialityImpact'] = calculate_average_confidentialityImpact(list_cves_matching_keyword)
    risk_score['integrityImpact'] = calculate_average_integrityImpact(list_cves_matching_keyword)
    risk_score['availabilityImpact'] = calculate_average_availabilityImpact(list_cves_matching_keyword)
    risk_score['privilegesRequired'] = calculate_average_privilegesRequired(list_cves_matching_keyword)
    #risk_score['matchingCveIds'] = [cve["cve_id"] for cve in list_cves_matching_keyword]#returns a list of related cve

    return risk_score

def get_enterprise_techniques_risk_scores():


    output_file_path=r"..\CLI_py_utils_by_fkg_cs\Scraper Json\mapping_results"

    mitre_attack_data = MitreAttackData("../../Janus/json/json_matrix/ics-attack.json")
    techniques = mitre_attack_data.get_techniques(remove_revoked_deprecated=True)

    print("----------Scraping CVSS3.1 metrics for all ICS techniques------------")
    print(f"Saving score mapping results of techniques in: {output_file_path}")

    min_score = 99  # set to higher value than scale so at first iteration the first score is set as minimum
    max_score = 0
    n_scores = 0
    sumof_scores = 0
    average_score = 0
    scores=[]

    #format of csv is Technique ATT&CK ID, [risk_score dictionary],'matchingCveIds': ['CVE-2024-0007',....., 'CVE-2024-0008'] list of cve ids matching
    output_string = "TECHNIQUE ATT&CK ID, CONGLOMERATE CVSS 3.1 RISK SCORES FROM CVE SCRAPING, LIST OF CVE ID MATCHING TECHNIQUE\n"
    for technique in techniques:
        n_scores = n_scores + 1

        external_id = mitre_attack_data.get_attack_id(technique.id)
        risk_scores = get_technique_risk_scores(technique.name)  # +" "+technique.description

        if risk_scores["baseScore"] == 0:
            risk_scores = get_technique_risk_scores(technique.name + " " + technique.description)  # perform search with more keywords

        score = risk_scores['baseScore']
        sumof_scores = sumof_scores + score


        if score < min_score:
            min_score = score
        if score > max_score:
            max_score = score
        output_string += f"{external_id},{risk_scores}\n"
        scores.append(risk_scores['baseScore'])

    #scrivo su file
    with open('mapping_results\ics_techniques_riskscores_mapping.csv', 'w') as file:
        # Scriviamo la stringa nel file
        file.write(f'{output_string}')
    print("------------------------DONE SCRAPING-------------------------------")
    print("------------------------STATISTICS OF ICS SCORES-------------------------------")
    print("MINIMUM SCORE: ", min_score)
    print("MAXIMUM SCORE: ",max_score)
    average_score=round(sumof_scores/n_scores,2)
    print("AVERAGE SCORE: ",average_score)
    print("NUMBER OF TECHNIQUES MAPPED: ",len(techniques))

    # Creazione del grafico
    plt.plot(scores)
    plt.ylim(0, 10)
    plt.axhline(y=average_score, color='r', linestyle='--', label=f'Media: {average_score}')
    # Aggiunta di etichette
    plt.xlabel('Numero di tecniche')
    plt.ylabel('Valore Basescore')
    plt.title('Grafico dei risk scores calcolati per le tecniche in ICS')
    # Aggiunta della legenda
    plt.legend()
    # Mostrare il grafico
    plt.show()



if __name__ == "__main__":
    #test scraping if class runned
    get_enterprise_techniques_risk_scores()
