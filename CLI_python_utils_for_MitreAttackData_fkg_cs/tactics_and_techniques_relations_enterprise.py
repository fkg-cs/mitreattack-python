from mitreattack.stix20.MitreAttackData import MitreAttackData


def main():
    n_tactics=0
    n_techniques=0
    n_subtechniques=0

    mitre_attack_data = MitreAttackData("../Janus/json/json_matrix/enterprise-attack.json")
    tactics = mitre_attack_data.get_tactics(remove_revoked_deprecated=True)

    n_tactics=len(tactics)
    print("-----TACTICS AND TECHNIQUES RELATIONS IN ENTERPRISE ATT&CK-----\n")
    # print(tactics[0].serialize(pretty=True))#stampa per vedere struttura oggetto stix
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
            # devo iterare sulle external references sono multiple e NON SEMPRE NELLO STESSO ORDINE, altrimenti rischio di avere l'id attack nullo
            for ref in external_references:
                if (
                        ref.get("source_name") == 'mitre-attack'):  # assegno solo se mi trovo nella external reference di mitre attack
                    technique_external_id = ref.get("external_id")

            print(f"   {i}.{j}) {technique.name} (ATT&CK ID: {technique_external_id}): {technique.description}")  #: {technique.description}#stampa descrizione ma riduce legibilità

            subs = mitre_attack_data.get_subtechniques_of_technique(technique.id)
            n_subtechniques = n_subtechniques + len(subs)  # conto totale sottotecniche

            if len(subs) >= 1:
                print(f"   There are {len(subs)} subtechniques related to {technique.name} techinique:")
                k = 0
                for s in subs:
                    k = k + 1
                    sub = s["object"]
                    print(f"     {i}.{j}.{k}) {sub.name} (ATT&CK ID: {mitre_attack_data.get_attack_id(sub.id)})")

    print(f"\n --> REPORT: {n_tactics} TACTICS FOUND , {n_techniques} TECHNIQUES FOUND , {n_subtechniques} SUBTECHNIQUES FOUND <--\n")

if __name__ == "__main__":
    main()
