# Our modules
import core
import helpers

import sys
from atlassian import Jira
import requests


def get_jira_auth(config_jira_object):
    """
    Performs authentication with the Jira server.
    :param config_jira_object: Jira subsection of config file
    :return: Type 'Jira' object
    """
    # username, password, cookie_dict, jira_access_token = None, None, None, None
    try:
        jira_url = config_jira_object["url"]
        jira_auth_method = config_jira_object["auth_method"]
        username = config_jira_object["credentials"]["userpass"]["username"]
        password = config_jira_object["credentials"]["userpass"]["password"]
        cookie_dict = config_jira_object["credentials"]["cookie"]
        jira_access_token = config_jira_object["credentials"]["access_token"]

    except KeyError:
        # There is something wrong with config file
        core.log_and_print("critical", "Could not read Jira configuration.")
        core.critical_cleanup()
        sys.exit(helpers.EXIT_JIRA_ERROR)

    jira = None
    try:
        if jira_auth_method == "userpass":
            jira = Jira(
                url=jira_url,
                username=username,
                password=password)

        elif jira_auth_method == "cookie":
            jira = Jira(
                url=jira_url,
                cookies=cookie_dict)

        elif jira_auth_method == "pat":
            jira = Jira(
                url=jira_url,
                token=jira_access_token)
        else:
            core.log_and_print("error", "Could not understand Jira authentication method: {}".format(jira_auth_method))

    except requests.exceptions.HTTPError as e:
        core.log_and_print("critical", "Could not authenticate to Jira server: {}".format(e.args))
        core.critical_cleanup()
        sys.exit(helpers.EXIT_JIRA_ERROR)

    return jira


def search_for_issues_vuln(config_jira_object, jira_query):
    """
    Searches for an issue in Jira server using ID, artifact and target image information as query params
    :param config_jira_object: Jira subsection of config JSON
    :param jira_query: Dict containing the information used to search for the issue
    :return: Returns the output of Jira server.
    """
    jira_project = config_jira_object["project"]
    jira_artifact = jira_query["artifact"]
    jira_target_image = jira_query["target_image"]
    jira_id = jira_query["id"]

    jql_request = 'project = {} AND text ~ {} AND text ~ {} AND text ~ {}'\
        .format(jira_project, jira_artifact, jira_id, jira_target_image)

    try:
        jira = get_jira_auth(config_jira_object)
        issues = jira.jql(jql_request)

    except requests.exceptions.HTTPError as e:
        core.log_and_print("critical", "Could not search Jira server: {}".format(e.args))
        core.critical_cleanup()
        sys.exit(helpers.EXIT_JIRA_ERROR)

    except requests.exceptions.ConnectionError as e:
        core.log_and_print("critical", "Could not connect to Jira server: {}".format(e.args))
        core.critical_cleanup()
        sys.exit(helpers.EXIT_JIRA_ERROR)

    else:
        return issues


def create_new_issue_id(config_jira_object, json_vuln):
    """
    Tells Jira server to create a new issue based on information provided in json_vuln dict.
    :param config_jira_object: Jira subsection of config JSON
    :param json_vuln: Dict containing all the necessary information to create the issue.
    :return: True, if successful; or exits with exception
    """
    # Jira issue types:
    # https://support.atlassian.com/jira-cloud-administration/docs/what-are-issue-types/

    project_key = config_jira_object["project"]
    issuetype_name = config_jira_object["issuetype"]
    target_image = json_vuln["target_image"]
    vuln_id = json_vuln["id"]
    description = json_vuln["description"]
    severity = json_vuln["severity"]
    artifact = json_vuln["artifact"]
    installed_version = json_vuln["installed_version"]

    cvss_v2score, cvss_v3score = 0, 0
    cvss_v2vector, cvss_v3vector = None, None
    try:
        cvss_v2score = json_vuln["cvss_v2score"]
        cvss_v2vector = json_vuln["cvss_v2vector"]
    except KeyError:
        pass

    try:
        cvss_v3score = json_vuln["cvss_v3score"]
        cvss_v3vector = json_vuln["cvss_v3vector"]
    except KeyError:
        pass

    fixed_version = json_vuln["fixed_version"]
    datasource = json_vuln["datasource"]
    datasource_nvd = json_vuln["datasource_nvd"]
    finding_type = json_vuln["finding_type"]
    fields = {
        "project": {'key': project_key},
        "issuetype": {'name': issuetype_name},
        "summary": "{}, {}, {}".format(vuln_id, artifact, target_image),
        "labels": [
            severity,
            finding_type
        ],
        "description": "Description: {}\n"
                       "Target image: {}\n"
                       "Artifact: {}\n"
                       "ID: {}\n"
                       "Severity: {}\n"
                       "CVSSv2 Score: {}\n"
                       "CVSSv2 Vector: {}\n"                       
                       "CVSSv3 Score: {}\n"
                       "CVSSv3 Vector: {}\n"
                       "Installed version: {}\n"
                       "Fixed version: {}\n"
                       "Datasource: {}\n"
                       "NIST NVD: {}\n"
                       "Finding Type: {}\n".format(description, target_image, artifact, vuln_id, severity,
                                                   cvss_v2score, cvss_v2vector, cvss_v3score, cvss_v3vector,
                                                   installed_version, fixed_version, datasource, datasource_nvd,
                                                   finding_type)
    }

    jira = get_jira_auth(config_jira_object)
    try:
        jira.issue_create(fields)
        core.log_and_print("info", "Jira issue created for {}, {}, {}".format(vuln_id, artifact, target_image))

    except requests.exceptions.HTTPError as e:
        core.log_and_print("error", "Could not create Jira issue: {}".format(e.args))
        core.critical_cleanup()
        sys.exit(helpers.EXIT_JIRA_ERROR)


def search_for_issues_image(config_jira_object, jira_query):
    """
    Searches for an issue in Jira server using target image information as query params
    :param config_jira_object: Jira subsection of config JSON
    :param jira_query: Dict containing the information used to search for the issue
    :return: Returns the output of Jira server.
    """
    jira_project = config_jira_object["project"]
    jira_target_image = jira_query["target_image"]

    jql_request = 'project = {} AND summary ~ "Findings for image {}"'\
        .format(jira_project, jira_target_image)

    try:
        jira = get_jira_auth(config_jira_object)
        issues = jira.jql(jql_request)

    except requests.exceptions.HTTPError as e:
        core.log_and_print("critical", "Could not search Jira server: {}".format(e.args))
        core.critical_cleanup()
        sys.exit(helpers.EXIT_JIRA_ERROR)

    except requests.exceptions.ConnectionError as e:
        core.log_and_print("critical", "Could not connect to Jira server: {}".format(e.args))
        core.critical_cleanup()
        sys.exit(helpers.EXIT_JIRA_ERROR)

    else:
        return issues


def create_new_issue_image(config_jira_object, json_vuln):
    """
    Tells Jira server to create a new issue based on information provided in json_vuln dict.
    :param config_jira_object: Jira subsection of config JSON
    :param json_vuln: Dict containing all the necessary information to create the issue.
    :return: True, if successful; or exits with exception
    """
    # Jira issue types:
    # https://support.atlassian.com/jira-cloud-administration/docs/what-are-issue-types/

    project_key = config_jira_object["project"]
    issuetype_name = config_jira_object["issuetype"]
    target_image = json_vuln["target_image"]
    table = json_vuln["table"]
    recommendation_message = json_vuln["recommendation"]["message"]
    recommendation_target = json_vuln["recommendation"]["target"]
    json_report = json_vuln["json"]

    fields = {
        "project": {'key': project_key},
        "issuetype": {'name': issuetype_name},
        "summary": "Findings for image {}".format(target_image),
        "description": "Target image: {}\n"
                       "Recommendation: {}\n"
                       "Targets: {}\n"
                       "{}\n".format(target_image, recommendation_message, recommendation_target, table)
    }

    jira = get_jira_auth(config_jira_object)
    try:
        jira.issue_create(fields)
        core.log_and_print("info", "Jira issue created for {}".format(target_image))

    except requests.exceptions.HTTPError as e:
        core.log_and_print("error", "Could not create Jira issue: {}".format(e.args))
        core.critical_cleanup()
        sys.exit(helpers.EXIT_JIRA_ERROR)


def check_jira_project_exists(config_jira_object):
    """
    Checks if the project name configured in the config JSON exists in Jira.
    :param config_jira_object: Jira subsection of config JSON
    :return: Jira response if found, None if not found.
    """
    jira = get_jira_auth(config_jira_object)
    result = None
    try:
        result = jira.project(config_jira_object["project"])

    except requests.exceptions.HTTPError as e:
        core.log_and_print("error", "Could not find Jira project {}: {}".format(config_jira_object["project"], e.args))

    except requests.exceptions.ConnectionError as e:
        core.log_and_print("error", "Could not connect to Jira. Is it running and ready? {}".format(e.args))

    return result


def check_jira_enabled(config_jira_object):
    """
    Checks the configuration for Jira integration in the config JSON.
    :param config_jira_object: Jira subsection of config JSON
    :return: True if Jira integration is enabled, False if it is not.
    """
    try:
        if config_jira_object["enabled"]:
            core.log_and_print("debug", "Jira integration is enabled.")
            return True
        core.log_and_print("debug", "Jira integration is disabled.")
        return False

    except KeyError:
        core.log_and_print("error", "Could not check Jira integration status.")
        return False
