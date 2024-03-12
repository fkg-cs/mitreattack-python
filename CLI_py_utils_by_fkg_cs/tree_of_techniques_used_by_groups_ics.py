from mitreattack.stix20 import MitreAttackData


def main():
    mitre_attack_data = MitreAttackData("../Janus/json/json_matrix/ics-attack.json")
    # ottengo tutti i gruppi operanti in enterprise
    groups = mitre_attack_data.get_groups(remove_revoked_deprecated=True)
    n_techniques = 0
    print("------- TREE OF TECHNIQUES USED BY EACH GROUP IN ICS-------")
    i_groups = 0
    for group in groups:
        i_groups = i_groups + 1
        techniques_used_by_group = mitre_attack_data.get_techniques_used_by_group(group.id)

        if len(techniques_used_by_group) > 0:
            print(f"{i_groups}) GROUP '{group.name}' was reported to use {len(techniques_used_by_group)} techniques:")
        else:
            print(f"{i_groups}) GROUP '{group.name}' was not associated with any technique.")

        n_techniques = n_techniques + len(techniques_used_by_group)

        i_techniques = 0
        for technique in techniques_used_by_group:
            i_techniques = i_techniques + 1
            technique_object = technique["object"]
            print(
                f"   {i_techniques}) {technique_object.name} (ATT&CK TECHNIQUE ID: {mitre_attack_data.get_attack_id(technique_object.id)})")
    print(f"\n --> REPORT: {len(groups)} GROUP FOUND , {n_techniques} TECHNIQUES USED BY THOSE GROUPS <--\n")


if __name__ == "__main__":
    main()
