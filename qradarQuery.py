import hashlib
import json
import os
import time
import requests
import logging
FORMAT = '%(asctime)-15s %(clientip)s %(user)-8s %(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger('qradar api')




import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


try:
    import ssl
except ImportError:
    print("error: no ssl support")


QRADAR_MACHINE_INDEX = 1
AUTH_TOKEN = "b97d995c-d6d1-4ada-a41c-1d2026bcf5a1"
QRADAR_HOST_IP = "9.148.245.251"


FLOW_ARRAY_STR = "flowArray"
RANGE_LEN = 50000
# total max results for query is: MAX_FLOWS_RESULTS_ITER * RANGE_LEN
MAX_FLOWS_RESULTS_ITER = 200

MAX_QUERY_FOR_DEBUG = 5000


BASE_URL = "https://" + QRADAR_HOST_IP
SEARCH_QUERY_BASE_URL = BASE_URL + "/api/ariel/searches"
SEARCH_QUERY_URL = SEARCH_QUERY_BASE_URL + "?query_expression="


MAX_WAIT_FOR_COMPLETE_LEN = 500
INTERVAL_IN_SEC = 2

FLOWS_TOKEN_STR = "flows"
SEARCH_ID_STR = 'search_id'
STATUS_COMPLETE_STR = "completed"
STATUS_STR = "status"

BASE_HEADER = {'Accept': 'application/json', 'Content-Type': 'application/json',
               'Version': '9.0', 'SEC': AUTH_TOKEN}

CACHE_DIR = os.path.join("qradar_connector", "cache")
LIMIT = 100


def get_path(query):
    query_hash = hashlib.sha1(query.strip().encode('UTF-8')).hexdigest()
    return os.path.join(CACHE_DIR, f"resp_{query_hash}.json")


def cache_resp(resp, query):
    with open(get_path(query), 'w') as outfile:
        json.dump(resp, outfile)

def get_resp_from_cache(query):
    if not os.path.exists(get_path(query)):
        return None

    with open(get_path(query)) as json_file:
        data = json.load(json_file)
        print(f"resp exist in cache, query: {query}")
        return data



def flat_list(list):
    flat_list = []
    for sublist in list:
        for item in sublist:
            flat_list.append(item)
    return flat_list


def get_query_result_for_search_id(id, query):
    url = f"{SEARCH_QUERY_BASE_URL}/{id}/results"
    ret = []
    logger.debug(f"url: {url}")
    for i in range(0, MAX_FLOWS_RESULTS_ITER):
        header = BASE_HEADER.copy()
        header["Range"] = "items={0}-{1}".format(
            i*RANGE_LEN, (i+1)*RANGE_LEN-1)
        try:
            response = requests.get(url, headers=header, timeout=(
                10, 10), verify=False)  # old use , params=params)
            res = json.loads(response.text)
            
            if FLOWS_TOKEN_STR in res:
                logger.debug(f"get_query_result response len is {len(res[FLOWS_TOKEN_STR])}")
                ret.append(res[FLOWS_TOKEN_STR])

                if len(res[FLOWS_TOKEN_STR]) < RANGE_LEN:  # ravid check it
                    logger.debug(f"stop fetching data, num of flows is smaller than {RANGE_LEN}")
                    break
            else:
                if len(res) < RANGE_LEN:
                    logger.debug(f"stop fetching data, num of flows is smaller than {RANGE_LEN}")
                    break

        except requests.RequestException as e:
            logger.error('It timed out for url {0}, error {1}'.format(url, e))
            raise e
        except Exception as e1:
            logger.error(e1)
            if len(res) < RANGE_LEN:
                break
    logger.debug(f"End after {i} iterations")
    ret = flat_list(ret)
    return ret


def get_query_results(id, query):
    ret = None
    url = SEARCH_QUERY_BASE_URL + "/" + id

    for loop in range(0, MAX_WAIT_FOR_COMPLETE_LEN):
        response = requests.get(url, headers=BASE_HEADER, verify=False)
        res = json.loads(response.text)
        if len(res) > 0:
            #logger.debug("get_query_results response {0}".format(res))
            try:
                if res[STATUS_STR].lower() == STATUS_COMPLETE_STR:
                    logger.debug("query res is ready!!")
                    ret = get_query_result_for_search_id(id, query)
                    break
            except:  # status is not found
                pass
        time.sleep(INTERVAL_IN_SEC)
    if ret == None:
        raise Exception("Failed to query QRadar")
    return ret


def internal_ariel_search(query):
    res1 = "Undef"
    logger.debug(f"query_expression = {query}")
    t1 = time.time()
    url = SEARCH_QUERY_URL + query
    try:
        logger.debug(f"Start processing {query}")
        response = requests.post(url, headers=BASE_HEADER, verify=False)

        res1 = json.loads(response.text)
        res = res1[SEARCH_ID_STR]

        if len(res) > 0:
            ret = get_query_results(res, query)
        else:
            ret = {FLOW_ARRAY_STR: []}
        return ret
    except:
        logger.error(f"Error: response of query {url} is {res1} dosn't include {SEARCH_ID_STR}")
        raise ValueError("Invalid aql query  " + str(res1))


def get_query_tokens(features):
    fields = []
    for feature_key, feature in features.items():
        if 'qradar_token' in feature:
            fields.append(f"{feature['qradar_token']} as {feature_key}")
    return ", ".join(fields)


def save_query(features, query_filter, time_window):
    tokens = get_query_tokens(features)
    if len(query_filter) > 0:
        filter_clause = f" WHERE {query_filter}"

    ######### Save the filter before the qradar formating ###############
    query_to_save = {
        'time_window': time_window,
        "query": query_filter
    }
    #####################################
    query = f"select {tokens} from flows {filter_clause} LIMIT {LIMIT}  start \'{time_window[0]}\' stop \'{time_window[1]}\'\n"
    # save into file


    if os.path.exists("qradar_queries.json"):
        try:
            with open("qradar_queries.json", "r") as f:
                exists = json.load(f)

            with open("qradar_queries.json", "w") as f:
                to_dump = [query_to_save]
                for q in exists:
                    to_dump.append(q)

                json.dump(to_dump, f)

        except json.decoder.JSONDecodeError:
            f.close()
            with open("qradar_queries.json", "w") as f:
                json.dump(query_to_save, f)

    else:
        with open("qradar_queries.json", "w") as f:
            json.dump(query_to_save, f)


    with open('qradar_queries.txt', 'a') as handle:
        handle.write(query)

def ariel_search(features, query_filter, time_window, use_cache=True):
    # save_query(features, query_filter, time_window)

    if use_cache:
        resp = get_resp_from_cache(query_filter)
        if resp is not None:
            return resp

    tokens = get_query_tokens(features)
    if len(query_filter) > 0:
        filter_clause = f" WHERE {query_filter} "
    else:
        filter_clause = query_filter

    """
    if 'sourceip' in query_filter or 'destinationip' in query_filter:
        query = "select "

        if 'sourceip' in query_filter:
            query += f"sourceip, NETWORKNAME(sourceip), "

        if 'destinationip' in query_filter:
            query += f"destinationip, NETWORKNAME(destinationip), "

        query += f"flowdirection from flows {filter_clause} LIMIT 1 start \'{time_window[0]}\' stop \'{time_window[1]}\'"

    else:
    """
    query = f"select {tokens} from flows {filter_clause} LIMIT {LIMIT} start \'{time_window[0]}\' stop \'{time_window[1]}\'"

    resp = internal_ariel_search(query)
    print(f"send query: {query}")

    if use_cache and len(resp) > 0:
        cache_resp(resp, query_filter)
    else:
        print(f"empty resp from QRadar for {query}")

    return resp




