import pprint

from mitreattack.stix20 import MitreAttackData


def get_enterprise_matrix():
    n_tactics=0
    n_techniques=0
    n_subtechniques=0

    output_list = dict()

    mitre_attack_data = MitreAttackData(r"C:\Users\franc\Desktop\mitrepy\mitreattack-python\fkg_cs\json_matrix\enterprise-attack.json")
    tactics = mitre_attack_data.get_tactics(remove_revoked_deprecated=True)

    n_tactics=len(tactics)

    output_list['title'] = "ENTERPRISE ATT&CK MATRIX"
    output_list['header']=" -----TACTICS AND TECHNIQUES RELATIONS IN ENTERPRISE ATT&CK----- "
    # print(tactics[0].serialize(pretty=True))#stampa per vedere struttura oggetto stix
    output_list["tactics"]=[]

    for tactic in tactics:
        # gestione external references di ATT&CK (senza passare da oggetto STIX)
        attack_external_reference = tactic["external_references"][0]
        url = attack_external_reference["url"]
        external_id = attack_external_reference["external_id"] #id framework ATT&CK
        # fine gestione external references di ATT&CK
        my_tactic=dict()
        my_tactic["name"]=tactic.name
        my_tactic["external_id"]=external_id
        my_tactic["description"]=tactic.description
        my_tactic["url"]=url

        # recupero tecniche correate a tattica
        techniques = mitre_attack_data.get_techniques_by_tactic(
            tactic.x_mitre_shortname, "enterprise-attack", remove_revoked_deprecated=True)

        # stampa tecniche associate a tattica
        n_techniques=n_techniques+len(techniques)#conto totale tecniche

        my_tactic["techniques_intestation"]=f"There are {len(techniques)} techniques related to {tactic.name} tactic:"
        j = 0
        # print(techniques[2].serialize(pretty=True))  # stampa tecnica per vedere struttura oggetto stix
        my_tactic["techniques"]=[]

        for technique in techniques:
            my_technique = dict()
            my_technique["name"] = technique.name
            technique_external_id = technique["external_references"][0].get("external_id")
            my_technique["external_id"] = technique_external_id
            my_technique["description"] = technique.description
            my_technique["subtechniques"]=[]
            subs=mitre_attack_data.get_subtechniques_of_technique(technique.id)

            if len(subs) >= 1:
                my_technique["subtechniques_intestation"]=f"There are {len(subs)} subtechniques related to {technique.name} techinique:"
                n_subtechniques = n_subtechniques + len(subs)
                for s in subs:
                    my_subtechnique = dict()
                    sub = s["object"]#casto in oggetto
                    my_subtechnique["name"] = sub.name
                    my_subtechnique["external_id"] = mitre_attack_data.get_attack_id(sub.id)
                    my_subtechnique["description"] = sub.description

                    my_technique["subtechniques"].append(my_subtechnique)

            my_tactic["techniques"].append(my_technique)

        output_list["tactics"].append(my_tactic)

    output_list["report"]=f"--> REPORT: {n_tactics} TACTICS FOUND , {n_techniques} TECHNIQUES FOUND , {n_subtechniques} SUBTECHNIQUES FOUND <--"

    return output_list

if __name__ == "__main__":
    get_enterprise_matrix()
