import json

from qradarQuery import ariel_search


def load_feature_config():
    with open("config/features.json") as json_file:
        data = json.load(json_file)
        return data







if __name__ == "__main__":
    try:


        with open("qradar_queries.json", "r") as f:
            queries = json.load(f)

        for query in queries:
            ariel_search(features=load_feature_config(), query_filter=query['query'], time_window=query['time_window'],
                         use_cache=False) # Need to be replaced with the method that queries the real QRadar


    except Exception as e:
        print(e)
        exit(1)











