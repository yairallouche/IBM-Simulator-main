from os.path import join
from datetime import datetime


# - - - - - - - - - - - - - - - - - PATHS - - - - - - - - - - - - - - - - -

TIME_STAMP_PATH = join("resources", "time_gap_list.json")

# Folders
results_folder = "results"
resource_folder = "resources"
dictionaries_folder = join(resource_folder, "dictionaries")
attack_flows_folder = join(resource_folder, "attack_flows")

# Files
engine_dict_structure_path = join(dictionaries_folder, "engine_dict_structure.json")
connection_dict_structure_path = join(dictionaries_folder, "connection_dict_structure.json")
mitre_db_path = join(resource_folder, "mitre_knowledge.csv")
connection_dict_path = join(dictionaries_folder, "connection_dict.json")

features_path = join(resource_folder, "features.json")

simulations_path = join(attack_flows_folder, "simulations.json")

start_time_dict = join(dictionaries_folder, "start_time_dict.json")
end_time_dict = join(dictionaries_folder, "end_time_dict.json")

default_network_list_path = join(dictionaries_folder, "default_network_list.json")

# - - - - - - - - - - - - - - - - - CONSTANTS - - - - - - - - - - - - - - - - -

# QRADAR
CACHE = True

# QUERY RESULT
MIN_TIME_IN_SECONDS = 600.0
MAX_TIME_IN_SECONDS = 3600.0
INCREASE_FACTOR = 1.5

# TIME
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
START_DATA_AND_TIME = "2020-01-01 00:00:00"
# END_DATA_AND_TIME = datetime.now().strftime(TIME_FORMAT)  # now
END_DATA_AND_TIME = datetime.now().strftime(TIME_FORMAT)  # now
start_time = None  # set time for first flow (example: start_time = "2020-01-01 00:00:00", should be in the save format at the Configuration)

# HANDLES
HOSTS_LIMIT = 5
TRY_LIMIT = 1

# CONFIGURATION CONSTANT
MY_IP_NAME = "myip"
USE_NETWORK_NAMES = True
IPS_FIELDS = ['sourceip', 'destinationip']
SOURCE_IP_TOKEN = 'sourceip'
SOURCE_NETWORK_TOKEN = 'source_network'
DESTINATION_IP_TOKEN = 'destinationip'
DESTINATION_NETWORK_TOKEN = 'destination_network'
DESTINATION_PORT_TOKEN = 'destinationport'
NETWORK_FEATURE_TOKEN = 'network'
ATTACK_FEATURE_TOKEN = 'alert'
