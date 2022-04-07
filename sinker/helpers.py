import os
import sys
import json

# Our modules
import core
import __version__

# Hardcoded variables:
# __version__ = '0.1'

# Default exit signals can be changed using config file
EXIT_OK = 0
EXIT_FAIL_LOW = 1
EXIT_FAIL_MEDIUM = 2
EXIT_FAIL_HIGH = 3
EXIT_FAIL_CRITICAL = 4

# Hardcoded signals
EXIT_NOOP = 10
EXIT_ROOT = 11
EXIT_NOT_WRITABLE = 12
EXIT_FILE_NOT_FOUND = 13
# EXIT_INVALID_SOURCE = 14
EXIT_INVALID_CONFIG = 15
EXIT_FILE_FORMAT = 16
EXIT_JSON_FILE = 17
EXIT_INVALID_VULNDB = 18
EXIT_INVALID_TARGETS = 19
EXIT_INVALID_SCANNER = 20
EXIT_INVALID_LOGIN = 21
EXIT_JIRA_ERROR = 22


def print_version():
    core.log_and_print("info", "\nSinker v{}\n".format(__version__.__version__))
    return True     # Do not remove, used in main scope, in-line condition


def running_as_root():
    core.log_and_print("critical",
                       "To reduce risks, do not run as root. To ignore this warning, use flag --ignore-root.")
    # No need to call core.critical_cleanup() because we haven't run anything yet.
    sys.exit(EXIT_ROOT)


def dest_not_writable(dest):
    core.log_and_print("critical", "Destination is not writable: {}".format(dest))
    core.critical_cleanup()
    sys.exit(EXIT_NOT_WRITABLE)


def missing_config(config_file):
    core.log_and_print("critical", "Could not locate or understand config file: {}".format(config_file))
    core.critical_cleanup()
    sys.exit(EXIT_INVALID_CONFIG)


def missing_targets(target):
    core.log_and_print("critical", "Could not locate config file: {}".format(target))
    core.critical_cleanup()
    sys.exit(EXIT_INVALID_TARGETS)


def missing_vulndb(cache_dir):
    core.log_and_print("critical", "Could not locate vulnerabilities DB: {}".format(cache_dir))
    core.critical_cleanup()
    sys.exit(EXIT_INVALID_VULNDB)


def noop():
    core.log_and_print("info", "All scans skipped and clean up not set. Nothing to do here.")
    # No need to call core.critical_cleanup() because we haven't run anything yet.
    sys.exit(EXIT_NOOP)


def sanity_checks():
    """
    Runs a few basic checks before start scanning, not to waste users' time.
    Pythonic way is EAFP: https://docs.python.org/3/glossary.html#term-EAFP
    Called by main().
    :return:
    """
    # Check if running as root (should not):
    core.bool_ignore_running_as_root or os.geteuid() == 0 and running_as_root()

    # Check if an operation was selected:
    # (core.args.skipSnyk and core.args.skipGrype and core.args.skipTrivy and not core.args.onlyCleanup) \
    #     and noop()

    # So far, so good. Let's print version and move on.
    print_version()


def find_values(query, json_repr):
    # https://stackoverflow.com/questions/14048948/how-to-find-a-particular-json-value-by-key
    results = []

    def _decode_dict(a_dict):
        try:
            results.append(a_dict[query])
        except KeyError:
            pass
        return a_dict

    json.loads(json_repr, object_hook=_decode_dict)  # Return value ignored
    return results
