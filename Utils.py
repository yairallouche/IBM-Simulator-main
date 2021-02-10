import json
import socket
import time
from random import randrange
# from random import randrange
from datetime import datetime, timedelta, date
from time import strptime, mktime, strftime, localtime
import os
import Configuration


def compare_dictionary_structs(dictionary: dict, dict_template: dict) -> None:
    """
    Compare dictionary structure to another dictionary structure.

    :param dictionary: Dictionary. a given that it structure need be check.
    :param dict_template: Dictionary. a given Dictionary with the right Structure.

    :return: True if the second dictionary structure is that same as the
                    given first dictionary, Otherwise, will return False.
    """
    for key, value in dict_template.items():
        if key.startswith("(optional)"):
            continue
        elif key not in list(dictionary.keys()) or not isinstance(dict_template[key], type(dictionary[key])):
            return False
        elif isinstance(dict_template[key], dict):
            sub_dict_1 = dictionary[key]
            sub_dict_2 = dict_template[key]
            if not compare_dictionary_structs(sub_dict_1, sub_dict_2):
                return False
    return True


def get_file_data(file_name):
    """
    Encapsulate all the file data extraction functionality
    :param file_name: String. path to the file (can be with .json or with out)
    :return: Dictionary. The file contents
    """
    file_name = file_name.replace(".json", "")
    with open(f"{file_name}.json", 'r') as file:
        data = json.load(file)

    return data


def load_json(file_path: str) -> dict:
    """
    Load file by it path.

    :param file_path: String. path to the file.

    :return: Object. The file contents.
    """
    with open(file_path, 'r') as file:
        data = json.load(file)

    return data


def save_json(destination_path: str, obj: object) -> None:
    """

    :param destination_path:  String. path to the file.
    :param obj: Object. The file contents.

    :return: None.
    """
    if not os.path.exists(Configuration.results_folder):
        os.makedirs(Configuration.results_folder)

    with open(destination_path, "w") as handle:
        handle.write(json.dumps(obj, indent=4))


def load_features(attack_filter=[]) -> dict:
    """
    This function return the features according to the default features
    and the given attack filter features.

    :return: Dictionary contain features.
    """
    features = load_json(Configuration.features_path)

    for feature in attack_filter:
        features[feature]['reference_flows'] = "alert"

    return features


# TIME FUNCTION
def get_formated_time(date: date, delta_seconds=0) -> date:
    """
    This function get date and delta in second and return date calculated as starting at the given date
    and after added the given delta in seconds.

    :param date: Date. base date.
    :param delta_seconds: Int. delta in second.

    :return: Date. the date calculated by the given arguments.
    """
    date = date + timedelta(seconds=delta_seconds)

    # return date.strftime(Configuration.TIME_FORMAT)
    return date


def get_time_window_size(time_window: list) -> float:
    """
    This function get list of two time windows and return the delta beterrn them in second.

    :param time_window: List. contatin teo dates, time between them will be measure.

    :return: Long. delta in second between the two given dates as a long.
    """
    start_utc = mktime(strptime(time_window[0], Configuration.TIME_FORMAT))
    end_utc = mktime(strptime(time_window[1], Configuration.TIME_FORMAT))
    time_window_size_sec = end_utc - start_utc

    return time_window_size_sec


def str_to_utc(time_as_string: str, format=Configuration.TIME_FORMAT) -> date:
    """
    This function cast a date and time as a string representation to a date object and return it

    :param time_as_string: String. time and date as a string by the Configuration format.
    :param format: String. format for parse the given string.

    :return: Date. date object represent the given date as a stirng.
    """
    return mktime(strptime(time_as_string, format))


def utc_to_str(time_utc: date, format=Configuration.TIME_FORMAT) -> str:
    """
    This function cast a given time date to string according to the given format at the Configuration file.

    :param time_utc: Date.
    :param format: String. format for parse the given string.

    :return: String. representation of the date as a string.
    """
    return time_utc.strftime(format)


def generate_random_date(start_date_and_time: date, end_date_and_time: date) -> str:
    """
    This function get two dates and return a random date and time between them.

    :param start_date_and_time: Date. represent the start date possible.
    :param end_date_and_time: Date. represent the end date possible.

    :return: String. a random date and time represent by string.
    """
    delta = end_date_and_time - start_date_and_time
    int_delta = (delta.days * 24 * 60 * 60) + delta.seconds
    random_second = randrange(int_delta)

    return start_date_and_time + timedelta(seconds=random_second)


def convert_string_to_datetime(datetime_as_string: str, format=Configuration.TIME_FORMAT) -> datetime:
    """
    This function get datetime object as a string and convert it to datetime object.

    :param datetime_as_string: String. datetime representation by the format.
    :param format: String. format for parse the given string.

    :return: datetime. datetime object represent the given string.
    """
    return datetime.strptime(datetime_as_string, format)


def current_milli_time() -> int:
    """
    Get current time in miliseconds.

    :return: Int. millisecond representing the current time.
    """
    return round(time.time() * 1000)


def time_and_date_to_mili(time_and_date: str, format=Configuration.TIME_FORMAT) -> int:
    """
    This function get a time and date at the

    :param time_and_date:
    :param format: String. format for parse the given string.

    :return: Int. representation of the given date and time in milliseconds.
    """
    return time.strptime(time_and_date, format)



def get_ip() -> str:
    """
    This function return the current IP of the machine as a string.
    :return: String. machine IP.
    """
    try:
        return socket.gethostbyname_ex(socket.gethostname())[-1][-1]
    except Exception as e:
        print(f"failed to load machine IP. \n\n{e.with_traceback()}")


if __name__ == "__main__":

    start_date = date(2020, 1, 1)
    end_date = date(2020, 2, 1)
    for _ in range(100):
        random_date = generate_random_date(start_date, end_date)
        print(random_date)

    print(get_time_window_size(['2020-02-02 10:00:00', '2020-02-02 10:01:00']))

