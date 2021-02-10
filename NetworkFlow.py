import Utils
import Configuration
from Ranker import Ranker
from Query import Query
from copy import deepcopy


class NetworkFlow:

    def __init__(self, connector, attack_dict):

        self.connector = connector
        self.network_flows = []

        self.IPs_state = 0
        self.IPs = set()

        self.ports = set()
        self.ports_state = 0

        self.features = None
        self.filters = None
        self.default = False
        self.attacker = None
        self.target = None

        self.next_flow = {
            "one-to-many-hosts": self.get_next_ip,
            "one-to-many-processes": self.get_next_port,
            "one-to-one": self.get_most_relevant_flow
        }
        self.attack_data = attack_dict

    def get_network_flows(self, features, filters: Query) -> None:
        """
        This method try to preform connection to it QRadar Connector with the given arguments.
        for each connection attempt it generate a random date and increase the time interval
        to get a better results.

        :param features: Dictionary. Containing all relevant field
        :param filters: String. The query with all the filters
        :return:
        """
        self.features = features
        self.filters = filters
        self.network_flows = self.handle_flows()
        self.restart_state(cleanup=True)

    def rank(self, ranker: Ranker) -> None:
        """
        This function get Ranker and use it the rank the network flows.

        :param ranker: Ranker. ranker that contain specific relevant rank functionality.

        :return: None.
        """
        self.network_flows = ranker.rank(self.network_flows)

    def __getitem__(self, index):
        return self.network_flows[index]

    def __setitem__(self, key, value):
        self.network_flows[key] = value

    def __iter__(self):
        if self.ports_state != 0:
            self.no = self.ports_state
        elif self.IPs_state != 0:
            self.no = self.IPs_state
        else:
            self.no = 0
        return self

    def __next__(self):
        flow_no = self.no
        self.no += 1
        return self.network_flows[flow_no]

    def update_state(self, flows):
        """
        This method will be responsible to update the state of the object.
        A state is defined as:
         ports, and flows from the network flows list that used those ports
         ip, and flows from the network flows list that used those ip
        For example:
            State 1: ports: [80] ports_state: 1, ip: [1.1.1.1] ip_state: 1
        A change occurred and the object had to change states after revealing a new flow with a new port. As a result:
            State 2: ports: [80,53] ports_state: 2 ip: [1.1.1.1] ip_state: 1
        A change occurred and the object had to change states after revealing a new flow with a new ip. As a result:
            State 3: ports: [80,53] ports_state: 2 ip: [1.1.1.1, 1.1.1.2] ip_state: 2
        :param flows: List. Containing flows that were returned from QRadar or Dict. of a single flow
        :return:
        """
        if flows is None:
            return

        if isinstance(flows, dict):
            flows = [flows]

        for flow in flows:
            self.IPs_state += 1
            self.IPs.add(flow[Configuration.DESTINATION_IP_TOKEN])

            self.ports_state += 1
            self.ports.add(flow[Configuration.DESTINATION_PORT_TOKEN])

    def restart_state(self, cleanup=False):
        """
        This method will reset the state of the object back to the first state.
        The reset can be a cleanup reset - meaning that all the past information is deleted and the object is
        returned to the initial state. Or a soft reset where only part of the past information - the flows number,
        is deleted.

        :param cleanup: boolean. Indicates whether to to a cleanup or soft reset. Defaults to soft
        :return: None
        """
        if cleanup:
            self.IPs.clear()
            self.ports.clear()

        self.IPs_state = 0
        self.ports_state = 0

    def get_next_ip(self, attack_flow: dict, inverted=False) -> dict:
        """
        This method return new flow with a new destination IP.

        :return: Dictionary. flow represent by dictionary with new
                    destination IP, if there is no new destination IP will return None.
        """

        for i in range(self.IPs_state, len(self.network_flows)):
            current_destination_ip = self.network_flows[i][Configuration.DESTINATION_IP_TOKEN]

            if current_destination_ip not in self.IPs:
                current_destination_port = self.network_flows[i][Configuration.DESTINATION_PORT_TOKEN]
                self.ports.add(current_destination_port)
                self.IPs.add(current_destination_ip)
                self.IPs_state = i + 1

                return self.network_flows[i]

        return None

    def get_next_port(self, attack_flow: dict, inverted=False) -> dict:
        """
        This method return new attack flow with a new destination port.

        :return: Dictionary. flow represent by dictionary with new
                    destination port, if there is no new destination port will return None.
        """
        if not self.attacker:
            #  Update the first flow to be reference as the attacker and victim - only return
            #  flows that match the reference
            self.attacker = attack_flow[Configuration.SOURCE_IP_TOKEN]
            self.target = attack_flow[Configuration.DESTINATION_IP_TOKEN]

        for i in range(self.ports_state, len(self.network_flows)):
            current_destination_port = self.network_flows[i][Configuration.DESTINATION_PORT_TOKEN]

            if current_destination_port not in self.ports:
                # update destination IPs list
                current_destination_ip = self.network_flows[i][Configuration.DESTINATION_IP_TOKEN]
                current_source_ip = self.network_flows[i][Configuration.SOURCE_IP_TOKEN]
                if current_destination_ip == self.target and current_source_ip == self.attacker:
                    #  Only return flows that match the attacker and victim
                    self.IPs.add(current_destination_ip)
                    # update destination ports list
                    self.ports.add(current_destination_port)
                    self.ports_state = i + 1
                elif inverted:
                    if current_destination_ip == self.attacker and current_source_ip == self.target:
                        #  Only return flows that match the attacker and victim
                        self.IPs.add(current_destination_ip)
                        # update destination ports list
                        self.ports.add(current_destination_port)
                        self.ports_state = i + 1

                else:
                    self.ports_state = i + 1
                    pass

                return self.network_flows[i]

        return None

    def handle_flows(self, simplified=False):
        """
        Method to handle the case of no result from the QRadar.

        :return: List. The network flows got from QRadar
        """
        flows_to_return = []
        LIMIT = Configuration.TRY_LIMIT  # number of attempt to get flows from QRadar
        copy_ports = []
        if Configuration.DESTINATION_PORT_TOKEN in self.attack_data['fields_filter'] and self.attack_data['fields_filter'][
            Configuration.DESTINATION_PORT_TOKEN]:
            copy_ports = self.attack_data['fields_filter'][Configuration.DESTINATION_PORT_TOKEN]
        for i in range(LIMIT):
            flows_to_return = self.get_flows()
            if flows_to_return:
                if copy_ports:  # If there are ports to check
                    for flow in flows_to_return:
                        if flow[Configuration.DESTINATION_PORT_TOKEN] in copy_ports:
                            copy_ports.remove(flow[Configuration.DESTINATION_PORT_TOKEN])

                if not copy_ports:  # If the query returned all the ports from the attack
                    #  The QRadar return results
                    break

                self.filters.simplify({Configuration.DESTINATION_PORT_TOKEN: copy_ports})  # Removing the ports we already found

        if not flows_to_return and not simplified:
            self.filters.simplify(Configuration.DESTINATION_NETWORK_TOKEN)
            flows_to_return = self.handle_flows(simplified=True)
            if flows_to_return:
                return flows_to_return

            self.filters.simplify(Configuration.SOURCE_IP_TOKEN)
            flows_to_return = self.handle_flows(simplified=True)
            if flows_to_return:
                return flows_to_return

        #  After the simplify if no results are returned take the default flows
        if not flows_to_return and not simplified:
            flows_to_return = Utils.load_json(Configuration.default_network_list_path)
            self.default = True

        return flows_to_return

    def get_flows(self) -> list:
        """
        The method is used to query the QRadar and handle the first case when there are no result.
        The first case will be to make the time window bigger by INCREASE_FACTOR which is configured in the
         Configuration and try again.
        It will try to make the window size bigger until MAX_TIME_IN_SECONDS which is configured in the Configuration.
        :return: List of network flows or None if no results were found in MAX_TIME_IN_SECONDS
        """
        # time_stamp_list = Utils.load_json(Configuration.TIME_STAMP_PATH)

        interval = Configuration.MIN_TIME_IN_SECONDS
        index = 0

        while interval <= Configuration.MAX_TIME_IN_SECONDS:
            start_datetime = Utils.convert_string_to_datetime(Configuration.START_DATA_AND_TIME)
            end_datetime = Utils.convert_string_to_datetime(Configuration.END_DATA_AND_TIME)

            random_start_date = Utils.generate_random_date(start_datetime, end_datetime)  # random date at given gap
            end_date = Utils.get_formated_time(random_start_date, interval)

            # time_stamp = time_stamp_list[index]
            # random_start_date = Utils.convert_string_to_datetime(time_stamp[0])
            # end_date = Utils.convert_string_to_datetime(time_stamp[1])

            networkflow_list = self.connector.query(
                features=self.features,
                query_filter=self.filters.get_query(),
                time_window_start=Utils.utc_to_str(random_start_date),
                time_window_end=Utils.utc_to_str(end_date)
            )
            if networkflow_list:
                # self.network_flows = networkflow_list
                # self.restart_state()  # Each result will force the object to into a new state

                return networkflow_list

            interval *= Configuration.INCREASE_FACTOR
            index += 1

        return None

    def get_most_relevant_flow(self, attack_flow: dict, inverted=False) -> dict:
        """
        This function get dictionary containing a relevant fields and iterate all existing flows and search flow that
        all the relevant field are equals to the relevant field value.

        :param attack_flow: Dictionary. referenced attack flow.

        :return: Dictionary. most relevant (close to the given dictionary) flow.
        """
        relevant_flow_features_values = {}

        for relevant_feature in self.attack_data["fields_filter"]:
            relevant_flow_features_values[relevant_feature] = attack_flow[relevant_feature]

        for flow in self:

            for relevant_feature in relevant_flow_features_values.keys():
                if flow[relevant_feature] != relevant_flow_features_values[relevant_feature]:
                    break
            self.update_state(flow)  # Prevent from iterating the same flow more than once
            return flow  # mean this low is fit to the relevant according to the description(features)

        return None  # didn't fount a relevant flow, return a default first flow

    def get_next_flow(self, attack_flow: dict, inverted: bool) -> dict:
        """
        This method will iterate through the network flows that have already returned from the QRadar and will find the
        next suitable flow for the attack type based on a new destination port or destination ip.

        :param attack_flow: Dict. The attack flow to merge.
        :param inverted: boolean. If the attack flow is a inverted flow.

        :return: Dict. new reference network flow.
        """
        #  Dynamically decide how to get the next flow: based on port or based on ip according to the attack type
        new_flow = self.next_flow[self.attack_data['attack_type']](attack_flow, inverted)
        if new_flow:
            return new_flow
        else:
            return self.network_flows[0]  # didn't found a relevant flow, return a default first flow
