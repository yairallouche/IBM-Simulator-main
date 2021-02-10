import json
import Configuration
from os.path import join
from qradarQuery import ariel_search
from Utils import compare_dictionary_structs, save_json


class Connector:

    def __init__(self, config: dict):
        """
        Constructor.

        :param config: Dictionary. containing the communication configuration.
        """
        self.config(config)
        self.load_features()
        if not self.test_connection():
            Configuration.CACHE = True

    def config(self, config_dict) -> None:
        """
        This method get a dictionary and verify it structure.
        if the given dictionary is valid it save as the
        connector configuration, else it will raise ValueError.

        :param config_dict: Dictionary. Connection configuration dictionary.

        :return: None
        """
        with open(Configuration.connection_dict_structure_path, 'r') as file:
            connector_config_template = json.load(file)
        if not compare_dictionary_structs(config_dict, connector_config_template):
            raise ValueError("the given connector dictionary doesnt contain the right structure.")
        self.config = config_dict

    def load_features(self) -> None:
        """
        This method load the connector's features.

        :return:None. raise ValueError in case th
        """
        with open(Configuration.connection_dict_structure_path, 'r') as file:
            self.features = json.load(file)

    def test_connection(self) -> bool:
        """
        This method check communication with the QRadar server.

        :return: Boolean. True if the communication working properly, False otherwise.
        """
        # TODO: implement
#        return qradarQuery.check_connection()
        return True

    def transform(self, json_attack: dict) -> dict:
        """
        This method get a pcap file as a dictionary and transform it to ARALE form using QRadar.

        :param json_attack: Dictionary. Simulation of attack as a pcap dictionary.

        :return: Dictionary. ARALE (QRadar flow) as a Dictionary.
        """
        # TODO: implement
        new_attack = {}

        # new_attack['flows'] = qradarQuery.transform(json_attack)
        new_attack['technique'] = input("please insert the technique name:")
        new_attack['source ip'] = new_attack['flows'][0]['sourceip']
        new_attack['destination ip'] = new_attack['flows'][0]['destinationip']
        new_attack['attack_type'] = input("please enter attack type (can be 'one-to-one', 'one-to-many-processes', 'one-to-many-hosts'):")
        new_attack['fields_filter'] = input("please enter attack fields_filter (can be each of the features the QRadar returned ('destinationport', 'protocolid', etc):")

        mitre_name = input("please enter MITRE technique number:")

        save_json(join(Configuration.attack_flows_folder, f"{mitre_name}.json"), new_attack)

        return new_attack

    def query(self, features: dict, query_filter: str, time_window_start: str, time_window_end: str) -> list:
        """
        The method get query params and using QRadar retrieved network flow samples.

        :param features: Dictionary. Features dictionary mapping all the feature names and properties.
        :param query_filter: String. Query constrains.
        :param time_window_start: String. Start time constrain represent by string.
        :param time_window_end: String. End time constrain represent by string.

        :return: List. All QRadar flows result according to the given feature and the constrains.
        """
        time_window = [time_window_start, time_window_end]
        return ariel_search(features, query_filter, time_window, Configuration.CACHE)

    def send(self, network_dict: list) -> bool:
        """
        This method send the given network flows to QRadar system.

        :param network_dict: List. Network that need to send to QRadar system.

        :return: Boolean. True if the send succeeded, False otherwise.
        """
        # TODO: implement

#        qradarQuery.inject_flows(network_dict)
        return True
