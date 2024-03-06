import pprint
from mitreattack.stix20 import MitreAttackData


def get_technique_info(id):
    output_list = dict()
    n_subtechniques=0
    mitre_attack_enterprise_data = MitreAttackData(
        r"C:\Users\franc\Desktop\mitrepy\mitreattack-python\fkg_cs\json_matrix\enterprise-attack.json")
    mitre_attack_ics_data = MitreAttackData(
        r"C:\Users\franc\Desktop\mitrepy\mitreattack-python\fkg_cs\json_matrix\ics-attack.json")
    output_list["external_id"] = id
    techniques = mitre_attack_enterprise_data.get_techniques(remove_revoked_deprecated=True)



    # print(techniques[2].serialize(pretty=True))  # stampa tecnica per vedere struttura oggetto stix
    for technique in techniques:
        technique_external_id = technique["external_references"][0].get("external_id")
        if technique_external_id == id:
            output_list["name"] = technique.name
            output_list["external_id"] = technique_external_id
            output_list["description"] = technique.description
            output_list["subtechniques"] = []
            subs = mitre_attack_enterprise_data.get_subtechniques_of_technique(technique.id)
            if len(subs) >= 1:
                output_list[
                    "subtechniques_intestation"] = f"There are {len(subs)} subtechniques related to {technique.name} techinique:"
                n_subtechniques = n_subtechniques + len(subs)
                for s in subs:
                    my_subtechnique = dict()
                    sub = s["object"]  # casto in oggetto
                    my_subtechnique["name"] = sub.name
                    my_subtechnique["external_id"] = mitre_attack_enterprise_data.get_attack_id(sub.id)
                    my_subtechnique["description"] = sub.description

                    output_list["subtechniques"].append(my_subtechnique)
    #pprint.pprint(output_list)
    return output_list

if __name__ == "__main__":
    get_technique_info("T1557")
