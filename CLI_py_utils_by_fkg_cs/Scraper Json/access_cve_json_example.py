
from Janus.model.CveData import CveData

def main():
    print(f"--> RETRIVING INFORMATION OF A CVE FROM ITS JSON FILE  <--\n")
    cve_json_data = CveData(r"..\Janus\json _CVE\2024\0xxx\0CVE-2024-0007.json")
    print(f"--> CVE ID: {cve_json_data.get_cveId()} ")
    print(f"--> PUBLISHING DATE: {cve_json_data.get_datePublished()}")
    print(f"--> CVE METRICS: ")
    #pprint.pprint(cve_json_data.get_metrics())#STAMPA DEBUG
    print(f"                BASE SCORE: [{cve_json_data.get_cvss_baseScore()}] ")
    print(f"                ATTACK COMPLEXITY: {cve_json_data.get_cvss_attackComplexity()} ")
    print(f"                ATTACK VECTOR: {cve_json_data.get_cvss_attackVector()} ")
    print(f"                ATTACK AVAILABILITY IMPACT: {cve_json_data.get_cvss_availabilityImpact()} ")
    print(f"                ATTACK BASE SEVERITY: {cve_json_data.get_cvss_baseSeverity()} ")
    print(f"                ATTACK CONFIDENTIALITY IMPACT: {cve_json_data.get_cvss_confidentialityImpact()} ")
    print(f"                ATTACK INTEGRITY IMPACT: {cve_json_data.get_cvss_integrityImpact()} ")
    print(f"                PRIVILEGES REQUIRED: {cve_json_data.get_cvss_privilegesRequired()} ")
    print(f"                SCOPE: {cve_json_data.get_cvss_scope()} ")
    print(f"                USER INTERACTION: {cve_json_data.get_cvss_userInteraction()} ")
    print(f"                VECTOR STRING: {cve_json_data.get_cvss_vectorString()} ")
    print(f"                VERSION: {cve_json_data.get_cvss_version()} ")


if __name__ == "__main__":
    main()
