import os
from os import walk
from os.path import join
from Utils import load_json, save_json
from Configuration import SOURCE_IP_TOKEN

def change_query_filter(filename):
    file_path = join(os.getcwd(), filename)

    attack_data = load_json(file_path)

    fields_filters = attack_data['fields_filter']
    attack_filters = {}

    for flow in attack_data['flows']:  # iterate all flows
        if flow[SOURCE_IP_TOKEN] == attack_data[SOURCE_IP_TOKEN]:  # check if the flow relevant by it direction
            for filter in fields_filters:  # iterate all relevant filters
                if flow[filter] is not None:
                    if filter in attack_filters:  # check if the key (filter) already exists in the attack filters
                        if not isinstance(attack_filters[filter], list):
                            if flow[filter] != attack_filters[filter]:  # check if value included in attack filter as a single value.
                                attack_filters[filter] = [attack_filters[filter]]
                                attack_filters[filter].append(flow[filter])

                        else:  # mean the attack filters relevant value is a list
                            if flow[filter] not in attack_filters[filter]:
                                attack_filters[filter].append(flow[filter])

                    else:  # filter doesn't exists as a key in thr attack filters, need to be added
                        attack_filters[filter] = [flow[filter]]
    
    # Replace all nulls with 0
    for flow in attack_data['flows']:
        for attr in flow:
            if flow[attr] is None:
                flow[attr] = 0
    
    fields = attack_data['fields_filter']
    attack_data['fields_filter'] = {}

    for field in fields:
        attack_data['fields_filter'][field] = attack_filters[field]

    save_json(file_path, attack_data)


def add_filter_value_list():
    _, _, filenames = next(walk(os.getcwd()))

    for filename in filenames:
        if filename.startswith("T") and filename.endswith(".json"):
            change_query_filter(filename)


if __name__ == "__main__":
    add_filter_value_list()
