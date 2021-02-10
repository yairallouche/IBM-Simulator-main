import pandas as pd
from Utils import save_json
from attackcti import attack_client
from Configuration import mitre_db_path
import os
import time

MITRE_RETENTION_TIME_IN_SEC = 60*60*24*30#30 days

class mitreConnector:
    """
    The class is wrapper for the mitre api.
    All related mitre tasks will be handled by the object
    """

    def __init__(self):
        """
        Constructor.
        Connect to the mitre database using the build-in api given by MITRE.
        If there is an error connecting to the database the local information stored on disc will be loaded instead.
        """

        if os.path.exists(mitre_db_path) and \
                (time.time() - os.path.getmtime(mitre_db_path) < MITRE_RETENTION_TIME_IN_SEC):
            self.__df = pd.read_csv(mitre_db_path,
                                    converters={"tactics": lambda x: x.strip("[]").replace("'", "").split(", "),
                                                "technique_name": lambda x: x.lower()})
            print("Loading Mitre DB completed")
            return

        try:
            print("Trying to connect to MITRE knowledge base...")
            self.__mitre_api = attack_client().get_enterprise(stix_format=False)
            print("Connection established")
            save_json("MITRE_1.json", self._mitreConnector__mitre_api)
            self.__df = None

        except Exception as e:
            print(f"Can't connect to mitre. Loading backup knowledge base from disc..., Ex {e}")
            self.__df = pd.read_csv(mitre_db_path,
                                    converters={"tactics": lambda x: x.strip("[]").replace("'", "").split(", "),
                                                "technique_name": lambda x: x.lower()})
            print("Loading Mitre DB completed")

    def __getitem__(self, item: str) -> dict:
        """
        Fetch all the information of the technique given
        :param item: String. Technique number or name - T1046 or Network Service Scanning
        :return: Dictionary - Contains all the relevant information of the technique from MITRE in the format of:
         {
        'tactics': [List of tactics],
        'technique_name': String
        'technique_id': String
        'technique_description': list
        'url': String
        }
        """
        if not self.__df:
            for mitre_info in self.__mitre_api['techniques']:
                #  Technique can be technique id - T1046 or technique name - Network Service Scanning
                if mitre_info['technique_id'].lower() == item.lower() or mitre_info['technique'].lower() == item.lower():
                    return {
                        'tactics': mitre_info['tactic'],
                        'technique_name': mitre_info['technique'],
                        'technique_id': mitre_info['technique_id'],
                        'technique_description': mitre_info['technique_description'],
                        'mitre_technique_url': mitre_info['url']
                    }
        else:
            try:
                result = self.__df.loc[self.__df['technique_id'] == item]
                if result.empty:
                    #  The item is not a technique id. Try technique name
                    result = self.__df.loc[self.__df['technique_name'] == item]

                result = result.to_dict()
                for key in result:  # Remove the line number from each value in the columns
                    column_value = result[key]
                    result[key] = column_value[list(column_value.keys())[0]]

                return result
            except IndexError:
                raise ValueError("Technique does not exist in the local database")

