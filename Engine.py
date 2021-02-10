import time
import Utils
import Configuration
from Query import Query
from os.path import join
from Ranker import Ranker
from Connector import Connector
from MITRE import mitreConnector
from NetworkFlow import NetworkFlow



class Engine:
    """
    Engine represent the main simulator class that able to simulate combine naive and attack combined.
    """

    def __init__(self):
        """
        Constructor.
        """
        self.config = None
        self.connect_qradar(Configuration.connection_dict_path)
        self.mitre_db_connector = get_mitre_api()
        self.ranker = Ranker()

    def set_engine_config(self, engine_config: dict) -> None:
        """
        This method get a engine dictionary and verify it.
        :param engine_config: Dictionary. Engine configuration.
                                Struct: {
                                        "technique": technique as a name or ID,
                                        "flow direction": L2L/L2R/R2L,
                                        (Optional)"source ip": X.X.X.X
                                        (Optional)"destination ip": X.X.X.X
                                        "output": {
                                            "save": True/False,
                                            (Optional)"dir": path to save results.
                                        }

        :return: None. if the given engine dictionary is not valid, will raise ValueError.
        """
        engine_config_template = Utils.get_file_data(Configuration.engine_dict_structure_path)
        if not Utils.compare_dictionary_structs(engine_config, engine_config_template):
            raise ValueError("the given engine dictionary doesnt contain the right structure.")
        self.config = engine_config

    def connect_qradar(self, config_path: str) -> None:
        """
        This method get a path to connection configuration file and verify it.

        :param config_path: String. Path to connection configuration file.

        :return: None. if the given engine dictionary is not valid, will raise ValueError.
        """
        connection_config_dict = Utils.get_file_data(config_path)
        self.connector = Connector(connection_config_dict)

    def merge(self, attack_dict: dict, network_flow: NetworkFlow, features: dict) -> list:
        """
        The method merge two NetworkFlows into one according to the technique that has benn chosen.

        :param attack_dict: Dictionary. contain all the attack data.list of attack flows that been retrieved
                                    from knowledge base, attack metadata.
        :param network_flow: NetworkFlow. object containing list of QRadar flows.
        :param features: Dictionary. contain all attack-network mapping.

        :return: List of NetworkFlow that represent the attack
        """
        attack_source_ip = attack_dict[Configuration.SOURCE_IP_TOKEN]

        if Configuration.start_time is None:
            attack_time = Utils.current_milli_time()
        else:
            date_and_time = Configuration.start_time
            attack_time = Utils.time_and_date_to_mili(date_and_time)

        base_attack_time = None
        current_attack_time_delta = 0

        merged = []

        for attack_flow in attack_dict["flows"]:
            inverted = False if attack_flow[Configuration.SOURCE_IP_TOKEN] == attack_source_ip else True  # check if the flow is inverted

            # Implement: NetworkFlow.get_next_flow iterator function class that will get the next attack flow
            # as an input and will. return the most close reference flow.
            network_reference_flow = network_flow.get_next_flow(attack_flow, inverted=inverted)

            # update 'starttime' section
            if base_attack_time is None:
                base_attack_time = attack_flow['starttime']
            else:
                current_attack_time_delta = attack_flow['starttime'] - base_attack_time

            # update current flow iteration if the flow inverted or not
            # attack_flow_tag = attack_flow if not inverted else inverted_flow(attack_flow)
            network_flow_tag = network_reference_flow if not inverted else inverted_flow(network_reference_flow)

            new_flow = {}
            for feature in features.keys():
                if 'time' == feature:
                    new_flow[feature] = attack_time + current_attack_time_delta
                elif Configuration.SOURCE_IP_TOKEN == feature:
                    if not inverted:
                        new_flow[feature] = self.config[Configuration.SOURCE_IP_TOKEN]
                    else:
                        new_flow[feature] = self.config[Configuration.DESTINATION_IP_TOKEN]
                elif Configuration.DESTINATION_IP_TOKEN == feature and Configuration.DESTINATION_IP_TOKEN in self.config:
                    if not inverted:
                        new_flow[feature] = self.config[Configuration.DESTINATION_IP_TOKEN]
                    else:
                        new_flow[feature] = self.config[Configuration.SOURCE_IP_TOKEN]
                elif Configuration.NETWORK_FEATURE_TOKEN == features[feature]['reference_flows']:  # network
                    new_flow[feature] = network_flow_tag[feature]
                elif Configuration.ATTACK_FEATURE_TOKEN == features[feature]['reference_flows']:  # alert(attack)
                    new_flow[feature] = attack_flow[feature]
                else:  # TBD (to be determined)
                    new_flow[feature] = attack_flow[feature]  # take alert(attack) randomly

            merged.append(new_flow)

        return merged

    def extract_query_filters(self):
        """
        This method gather filter from the engine dictionary and
        create a query for QRadar connector. if a given save word ('myip') in given under 'sourceip'
        the machine self ip will be used.
        :return: String. representation of filter to QRadar Connector contain user and attack filters.
        """
        if Configuration.SOURCE_IP_TOKEN in self.config and Configuration.MY_IP_NAME == self.config[Configuration.SOURCE_IP_TOKEN]:
            self.config[Configuration.SOURCE_IP_TOKEN] = Utils.get_ip()

        self.filters = Query(self.config)


    def run_simulation(self) -> list:
        """
        This method using the engine configuration, QRadar and mitre att@ck knowledge base to combine naive
        network traffic flows with a attack traffic flows and return the combine flows.

        :return: List. list of combined naive and attack traffic as a flows.
        """
        attack_dict = load_technique(self.config["technique"])  # attack_dict containing attack and metadata
        print("technique was loaded succesfuly ")
        features = Utils.load_features(attack_dict['fields_filter'])

        self.extract_query_filters()
        print(f"query filter was set to {self.filters.content}")

        network_flow = NetworkFlow(self.connector, attack_dict)
        network_flow.get_network_flows(features=features,
                                       filters=self.filters)

        print(f"pull {len(network_flow.network_flows)} network reference flows from QRadar")

        # ibm_networkflow = network_flow.rank(self.ranker)
        merged_network_flow = self.merge(attack_dict, network_flow, features)

        if self.config["output"]["save"]:
            if not "path" in self.config["output"]:
                self.config["output"]["path"] = join(Configuration.results_folder,
                                                     f"merge_flows- {self.config['technique']} - "
                                                     f"{time.strftime('%m-%d--%H-%M')}.json")

            Utils.save_json(self.config["output"]["path"], merged_network_flow)

        return merged_network_flow


    def inject_pcap(self, new_attack_pcap_json: dict) -> list:
        """
        This method get a pcap file as a json and usong QRadar convert it to arale json form
        :param new_attack_pcap_json:

        :return:
        """
        arale_json_flow = self.connector.transform(new_attack_pcap_json)

        return arale_json_flow


def get_mitre_api() -> mitreConnector:
    """
    This function pull all the Mitre Att@ck knowledge base object
    :return:
    """
    return mitreConnector()


def load_technique(technique: str) -> dict:
    """
    This function will fetch the technique flow that corresponds to the technique the user has given
    in the configuration.
    In addition, all flows that are not part of the technique and are considered "garbage" will be filtered.
    :param technique: String. The technique number

    :return: Dictionary containing the metadata of the attack an the flows
    """
    attacks_flows = Utils.load_json(join(Configuration.attack_flows_folder, f"{technique}.json"))
    flows = []

    try:
        for flow in attacks_flows['flows']:
            #  Filter flows that are not part of the attack metadata
            if flow[Configuration.SOURCE_IP_TOKEN] == attacks_flows[Configuration.SOURCE_IP_TOKEN] and \
                    flow[Configuration.DESTINATION_IP_TOKEN] in attacks_flows[Configuration.DESTINATION_IP_TOKEN]:
                flows.append(flow)

        attacks_flows['flows'] = flows

    except KeyError:
        # If we reach this point it means that the metadata of the source ip and dest ip are not configured
        # In that case no filter will be used on the flows and all flows will be taken by the engine
        pass

    return attacks_flows


def get_optional_filter() -> list:
    """
    This function return all the field that label as 'optional' according to the engine dictionary structure.

    :return: List. list of optional filter will be return.
    """
    engine_config_template = Utils.get_file_data(Configuration.engine_dict_structure_path)  #
    optional = "(optional)"

    optional_filters = []
    for engine_dict_key in engine_config_template.keys():
        if engine_dict_key.startswith(optional):
            engine_optional_key = engine_dict_key[len(optional):]
            optional_filters.append(engine_optional_key)

    return optional_filters


def inverted_flow(flow: dict) -> dict:
    """
    This function invert the given flow and return inversion flow.

    :param flow: Dictionary. represent flow to invert.

    :return: Dictionary. Invert flow in shape of dictionary.
    """
    invert_dict = {
        "flowdirection": flow["flowdirection"][::-1],
        "protocolid": flow["protocolid"],
        "applicationid": flow["applicationid"],
        "destinationport": flow["destinationport"],
        "destination_network": flow["source_network"],
        "source_network": flow["destination_network"],
        "destinationip": flow["sourceip"],
        "sourceip": flow["destinationip"],
        "sourcepackets": flow["destinationpackets"],
        "destinationpackets": flow["sourcepackets"],
        "sourcebytes": flow["destinationbytes"],
        "destinationbytes": flow["sourcebytes"],
        "sourceflags": flow["destinationflags"],
        "destinationflags": flow["sourceflags"],
        "starttime": flow["starttime"]
    }

    return invert_dict

