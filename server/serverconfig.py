import configparser

config = configparser.ConfigParser()
config.read("serverconfig.ini")


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
files = dict((x[0], handle_config_value(x[1])) for x in config.items("FILES"))



