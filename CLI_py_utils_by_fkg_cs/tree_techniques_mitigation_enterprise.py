from mitreattack.stix20 import MitreAttackData

def main():
    n_tactics=0
    n_techniques=0
    n_mitigations=0

    mitre_attack_data = MitreAttackData("../Janus/json/json_matrix/enterprise-attack.json")
    tactics = mitre_attack_data.get_tactics(remove_revoked_deprecated=True)

    n_tactics=len(tactics)
    print("-----MITIGATIONS OF TECHNIQUES OF TACTICS ENTERPISE-----\n")

    i = 0
    for tactic in tactics:
        i = i + 1
        # gestione external references di ATT&CK (senza passare da oggetto STIX)
        external_references = tactic["external_references"]
        for ref in external_references:
            url = ref["url"]
            external_id = ref.get("external_id") #id framework ATT&CK
        # fine gestione external references di ATT&CK
        print(f"\n{i}) {tactic.name} (ATT&CK ID: {external_id}) : {tactic.description}\n More at: {url}\n")

        # recupero tecniche correate a tattica
        techniques = mitre_attack_data.get_techniques_by_tactic(
            tactic.x_mitre_shortname, "enterprise-attack", remove_revoked_deprecated=True)

        # stampa tecniche associate a tattica
        n_techniques=n_techniques+len(techniques)#conto totale tecniche

        print(f"\nThere are {len(techniques)} techniques related to {tactic.name} tactic: \n")
        j = 0
        # print(techniques[2].serialize(pretty=True))  # stampa tecnica per vedere struttura oggetto stix
        for technique in techniques:
            j = j + 1
            external_references = technique["external_references"]
            mitigations_of_techinique = mitre_attack_data.get_mitigations_mitigating_technique(technique.id)
            # devo iterare sulle external references sono multiple, altrimenti rischio di avere l'id attack nullo
            for ref in external_references:
                if (ref.get("source_name") == 'mitre-attack'):  # assegno solo se mi trovo nella external reference di mitre attack
                    technique_external_id = ref.get("external_id")

            print(f"   {i}.{j}) {technique.name} (ATT&CK ID: {technique_external_id}) has {len(mitigations_of_techinique)} mitigations")  #: {technique.description}#stampa descrizione ma riduce legibilità
            n_mitigations=n_mitigations+len(mitigations_of_techinique)
            k=0
            if len(mitigations_of_techinique)>0: print(f"   MITIGATIONS:")#controllo se esistono mitigazioni
            else:
                print(f"        NO MITIGATIONS KNOWN")

            for mitigation in mitigations_of_techinique:
              #print(mitigation)
              k=k+1
              external_references = mitigation['object']['external_references']
              for ref in external_references:
                if (ref.get("source_name") == 'mitre-attack'):  # assegno solo se mi trovo nella external reference di mitre attack
                  mitigation_external_id = ref.get("external_id")
              print(f"     {i}.{j}.{k}) {mitigation['object']['name']} ( ATT&CK ID: {mitigation_external_id}): {mitigation['object']['description']}")

    print(f"\n --> REPORT: {n_tactics} TACTICS FOUND , {n_techniques} TECHNIQUES FOUND , {n_mitigations} MITIGATIONS FOUND <--\n")

if __name__ == "__main__":
    main()
