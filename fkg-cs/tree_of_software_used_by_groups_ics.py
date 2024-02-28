from mitreattack.stix20 import MitreAttackData
import pprint

def main():
    mitre_attack_data = MitreAttackData("ics-attack.json")

    # get all software related to groups
    all_software_used_by_all_groups = mitre_attack_data.get_all_software_used_by_all_groups()
    groups = mitre_attack_data.get_groups(remove_revoked_deprecated=True)
    #pprint.pprint(groups)
    print(f"Tree of Software kown to be used by Groups ({len(all_software_used_by_all_groups.keys())} groups):")
    i_groups = 0

    n_groups = len(groups)#contatore numero di gruppi TOTALI
    n_groups_using_software = len(all_software_used_by_all_groups)#contatore software usati da TUTTI gruppi
    n_software_used_by_all_groups =0#contatore software usati da TUTTI gruppi

    #variabili contenenti informazioni del gruppo che si sta analizzando
    group_name='none'
    group_external_id='GXXXXX'

    #pprint.pprint(all_software_used_by_all_groups.items())

    for id, software_used in all_software_used_by_all_groups.items():
        i_groups=i_groups+1
        #recupero grazie ad id stix il nome e l'external id mitre-attack scansionando ogni gruppo noto
        for group in groups:
            if group['id'] == id:
                group_name=group['name']
                group_external_id=group.external_references[0].external_id
        print(f"{i_groups}) GROUP '{group_name}' (ATT&CK ID: {group_external_id}) has used {len(software_used)} software in ICS ATT&CK:")


        n_software_used_by_all_groups=n_software_used_by_all_groups+ len(software_used)#aggiorno numero di software trovati
        i_software=0#azzero contatore sofrware usati da gruppo
        for software in software_used:#itero sui software usati da ogni gruppo
            i_software=i_software+1
            #pprint.pprint(software)
            print(f"    {i_software}) {software['object'].name} (ATT&CK SOFTWARE ID: {software['object'].external_references[0].external_id}): {software['object'].description}")#descrizione è stringa unica, non separabili le differenti citations

    print(f"\n --> REPORT: OUT OF {n_groups} GROUPS OPERATING IN ICS ATT&CK MATRIX CONTEXT , {n_groups_using_software} GROUPS ARE KNOWND TO USE {n_software_used_by_all_groups} SOFTWARES <--\n")



if __name__ == "__main__":
    main()
