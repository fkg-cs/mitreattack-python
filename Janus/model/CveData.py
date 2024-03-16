import json
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