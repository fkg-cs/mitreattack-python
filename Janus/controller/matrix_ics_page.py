import pprint
from mitreattack.stix20 import MitreAttackData


def get_ics_matrix():
    n_tactics = 0
    n_techniques = 0
    n_subtechniques = 0

    output_list = dict()

    mitre_attack_data = MitreAttackData(r"../Janus/json/json_matrix/ics-attack.json")
    tactics = mitre_attack_data.get_tactics(remove_revoked_deprecated=True)
    tactics.sort(key=lambda x: x["external_references"][0].get("external_id"), reverse=False)

    n_tactics = len(tactics)

    output_list['title'] = "ICS ATT&CK MATRIX"

    output_list["tactics"] = []

    for tactic in tactics:
        attack_external_reference = tactic["external_references"][0]
        url = attack_external_reference["url"]
        external_id = attack_external_reference["external_id"]
        my_tactic = dict()
        my_tactic["name"] = tactic.name
        my_tactic["external_id"] = external_id
        my_tactic["description"] = tactic.description
        my_tactic["url"] = url

        techniques = mitre_attack_data.get_techniques_by_tactic(
            tactic.x_mitre_shortname, "ics-attack", remove_revoked_deprecated=True)

        my_tactic["techniques_intestation"] = f"There are {len(techniques)} techniques related to {tactic.name} tactic:"
        my_tactic["techniques"] = []

        for technique in techniques:
            if technique.x_mitre_is_subtechnique == False:
                n_techniques = n_techniques + 1
                my_technique = dict()
                my_technique["name"] = technique.name
                technique_external_id = technique["external_references"][0].get("external_id")
                my_technique["external_id"] = technique_external_id
                my_technique["description"] = technique.description
                my_technique["subtechniques"] = []
                subs = mitre_attack_data.get_subtechniques_of_technique(technique.id)
                if len(subs) >= 1:
                    my_technique["subtechniques_intestation"] = f"There are {len(subs)} subtechniques related to {technique.name} techinique:"
                    n_subtechniques = n_subtechniques + len(subs)
                    for s in subs:
                        my_subtechnique = dict()
                        sub = s["object"]
                        my_subtechnique["name"] = sub.name
                        my_subtechnique["external_id"] = mitre_attack_data.get_attack_id(sub.id)
                        # my_subtechnique["description"] = sub.description

                        my_technique["subtechniques"].append(my_subtechnique)
                    my_technique["subtechniques"].sort(key=lambda x: x['external_id'], reverse=False)

                my_tactic["techniques"].append(my_technique)

        output_list["tactics"].append(my_tactic)

    output_list["report"] = f"RETRIVED: {n_tactics} TACTICS , {n_techniques} TECHNIQUES , {n_subtechniques} SUBTECHNIQUE."
    return output_list


if __name__ == "__main__":
    get_ics_matrix()
