class Ranker:
    """
    The class is a wrapper object for all the ranking of network flows
    """
    
    def __init__(self):
        """
        Constructor.        
        """
        pass

    def ranking_function(self, item):
        """
        The method decide how to rank each flow
        """
        # TODO: implement
        pass

    def rank(self, network_flows: list) -> list:
        """
        Rank the list of network flows based on the ranking function
        :param network_flows: List. each object is a network flow
        :return: List of sorted network flows from best to last
        """
        # return sorted(network_flows, key=self.rank_function, reverse=True) TODO:need to implement
        return network_flows[0]
