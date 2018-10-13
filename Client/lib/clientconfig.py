import configparser

"""
This module is just for extracting the variables from the config file,
converting them to their correct data type and returning them to the main program.
"""

config = configparser.ConfigParser()
config.read("clientconfig.ini")


def is_int_string(s):
    try:
        int(s)
        return True
    except ValueError:
        return False


def handle_config_value(value):
    if value in ("true", "false"):
        return value == "true"
    elif is_int_string(value):
        return int(value)
    else:
        return value


connection = dict((x[0], handle_config_value(x[1])) for x in config.items("CONNECTION"))
