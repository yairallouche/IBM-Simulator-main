import json
from os.path import join
from Engine import Engine
from Utils import load_json, save_json
from Configuration import resource_folder
import logging
import os

from utiles import log

origin_engine_dict = {
  "technique": None,
  "output": {
    "save": "True",
  }
}


def run_technique(engine, engine_config):
  print(f"start running technique with configuration:  {engine_config}")
  try:

    engine_dict_path = join(resource_folder, f"{current_engine_dict['technique']}_engine_dict.json")

    save_json(engine_dict_path, engine_config)

    engine_dict = load_json(engine_dict_path)
    engine.set_engine_config(engine_dict)

    combine_flows = engine.run_simulation()
    print(f"send the following {len(combine_flows)} flows to QRadar")
    print(json.dumps(combine_flows, indent=4, sort_keys=True))

  except Exception as e:
    print(f"Failed to run technique Ex {e}, run config: {engine_config}")


if __name__ == "__main__":
    log.init(level=logging.INFO, path=os.path.join(os.getcwd(), "store", "log"))

    # Query Extraction

    engine = Engine()
    # 1. source_ip + [list of ports] + destination ip


    current_engine_dict = origin_engine_dict.copy()

    current_engine_dict['technique'] = "T1046"
    current_engine_dict['sourceip'] = "9.6.189.157"
    current_engine_dict['destinationip'] = "9.85.151.16"


    flow_1 = run_technique(engine,current_engine_dict)
    #
    # 2a. [list of ports] + destination_ip
    current_engine_dict = origin_engine_dict.copy()

    current_engine_dict['technique'] = "T1046"
    current_engine_dict['destinationip'] = "9.85.151.16"

    flow_2a = run_technique(engine,current_engine_dict)

    # 2b. source_ip + + [list of ports] with no destination ip
    current_engine_dict = origin_engine_dict.copy()

    current_engine_dict['technique'] = "T1046"
    current_engine_dict['sourceip'] = "9.101.150.16"
    current_engine_dict['flowdirection'] = "L2L"

    flow_2b = run_technique(engine,current_engine_dict)

    #
    #
    # 3. source_ip + port + get list of hosts from the results
    current_engine_dict = origin_engine_dict.copy()

    current_engine_dict['technique'] = "T1021_004"
    current_engine_dict['sourceip'] = "9.27.82.225"
    current_engine_dict['flowdirection'] = "L2L"

    flow_3 = run_technique(engine,current_engine_dict)
    #
    #
    # 4. source_ip + destination_ip + one port
    current_engine_dict = origin_engine_dict.copy()

    current_engine_dict['technique'] = "T1087"
    current_engine_dict['sourceip'] = "9.59.34.88"
    current_engine_dict['destinationip'] = "9.250.243.50"

    flow_4 = run_technique(engine,current_engine_dict)

