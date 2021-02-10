import Configuration
from Utils import get_file_data


class Query:

    def __init__(self, config: dict):
        """
        Constructor.
        Takes the config given to him and create the initial query from the values in the config.

        :param config:  Dictionary. Configuration of the engine or other object that map the keys to values.
        The parameters in the config need to correspond to keys in the Configuration files.
        """
        self.content = {}
        self.query = ""
        self.config = config
        self.first = True
        engine_config_template = get_file_data(Configuration.engine_dict_structure_path)
        optional = "(optional)"
        for engine_dict_key in engine_config_template.keys():
            if engine_dict_key.startswith(optional):
                engine_optional_key = engine_dict_key[len(optional):]
                if engine_optional_key in self.config.keys():
                    self.content[engine_optional_key] = self.config[engine_optional_key]

    def __setitem__(self, key, value):
        if isinstance(value, list):
            for val in value:
                self.content[key] = val
        else:
            self.content[key] = value

    def simplify(self, to_remove: list):
        """
        The method will get a list of string (that exists in the query) to remove and will 'simplify' the query
         by removing the keys and their values from the query and making it more generic.

        :param to_remove: query tokens. For example: ['destinationip','sourceip'] or 'destinationip' or even
        {destinationip: '1.1.1.1'} -> will result of the value of 1.1.1.1 to removed from the query and not the entire
        destination ip token.
        """
        if isinstance(to_remove, str):
            to_remove = [to_remove]

        if isinstance(to_remove, list):
            for key in to_remove:
                if key in self.content:
                    self.content.pop(key)

        elif isinstance(to_remove, dict):
            for key in to_remove:
                if key in self.content:
                    self.content[key] = to_remove[key]

    def add_query_filter(self, query_filter: str, params: object, first=False):
        """
        This method create string according to QRadar syntax of a given field and it's value(s) given as a parameters.

        :param query_filter: string. represent the field.
        :param params: String\List. represent the value or values that the field is limited to.

        """
        base = "" if first else "and"  # check if this is the first query argument

        if isinstance(params, str):
            if first:
                if '(' in params:
                    self.query += f"{query_filter} in ({params}) "
                else:
                    if query_filter in Configuration.IPS_FIELDS and Configuration.USE_NETWORK_NAMES:
                        self.query += f"NETWORKNAME({query_filter}) in (NETWORKNAME('{params}')) "
                    else:
                        self.query += f"{query_filter} in ('{params}') "
            else:
                if query_filter in Configuration.IPS_FIELDS and Configuration.USE_NETWORK_NAMES:
                    self.query += f"{base} NETWORKNAME({query_filter}) in (NETWORKNAME('{params}')) "
                else:
                    self.query += f"{base} {query_filter} in ('{params}') "

        elif isinstance(params, list):
            if len(params) == 0:
                raise ValueError("can't create filter with empty list as parameter.")

            base += f"{query_filter} in ("
            for i, param in enumerate(params):
                if i != (len(params) - 1):  # check if the last to add
                    base += f"'{param}', "
                else:
                    base += f"'{param}'"
            base += ") "

            self.query += base
        else:
            raise ValueError(f"error occur with trying to build filter. filter can be string or list."
                             f"(filter: {query_filter}, parameters: {params}")

    def build(self) -> None:
        """
        The method will build the query again from the content it saved.

        :return: None.
        """
        self.query = ""
        self.first = True
        for key in self.content.keys():
            self.add_query_filter(key, self.content[key], first=self.first)
            self.first = False

    def add(self, item: dict):
        """
        The method will add the key and value mapped in the item to the query
        :param item: Dictionary. Contains keys and their values in String
        :return:
        """
        for k, v in item.items():
            if v:
                if isinstance(v, list):  # Lists should be converted to strings
                    self.content[k] = v
                else:
                    self.content[k] = str(v)

    def get_query(self) -> str:
        """
        The method will build the query from the content and returns it.

        :return: String. The query.
        """
        self.build()

        return self.query
