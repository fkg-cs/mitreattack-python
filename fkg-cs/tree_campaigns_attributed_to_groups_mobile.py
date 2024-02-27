from mitreattack.stix20 import MitreAttackData
import pprint
def main():
    mitre_attack_data = MitreAttackData("mobile-attack.json")

    #ottengo tutti i gruppi a cui sono state attribuite tutte le campagne
    groups_attributing = mitre_attack_data.get_all_groups_attributing_to_all_campaigns()

    print(f"Retrived {len(groups_attributing.keys())} MOBILE campaigns attributed to groups:")
    i=0
    for id, groups in groups_attributing.items():
        i=i+1
        print(f"{i}) {id} was attributed to {len(groups)} {'group' if len(groups) == 1 else 'groups'} :")
        # groups_attributing[id][0]['object'].name
        #pprint.pprint(groups)

        j=0
        for group in groups:
            j=j+1
            external_group_id = group['object'].external_references[0].external_id

            print(f"   {j}) {group['object'].name} (ATT&CK GROUP ID: {external_group_id})")


if __name__ == "__main__":
    main()
