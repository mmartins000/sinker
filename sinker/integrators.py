import core
import jira_helper
import parsers
import exporters

import copy


def send_to_integrations(config_object, json_sinker):
    """
    This function is the hub that distributes work to the integration functions.
    :param config_object: Config JSON
    :param json_sinker: JSON with the output for all scans
    :return: True
    """
    for app in config_object["integrations"]:
        if app == "jira":
            send_to_jira(config_object, json_sinker)


def send_to_jira(config_object, json_sinker):
    config_jira_object = config_object["integrations"]["jira"]

    # Are we using Jira?
    if not jira_helper.check_jira_enabled(config_jira_object):
        return

    # Does the project key informed by the user exist?
    result = jira_helper.check_jira_project_exists(config_jira_object)
    if result is not None:
        # result is not None, project exists
        if not result["key"] == config_jira_object["project"]:
            # Double-checking Jira result
            return
    else:
        # result == None, project does not exist
        return

    for target_image in json_sinker["reporting"]:

        # Code block A: Target image is public
        if parsers.check_image_in_public_registry(target_image):
            # Image was downloaded, not built at home
            # It doesn't make sense to create one issue for each vulnerability of an image we don't own
            json_copy = copy.deepcopy(json_sinker)
            for target in json_copy["reporting"]:
                # Remove all the other targets; we will create an issue for this image only
                if target != target_image:
                    json_copy.pop(target)

            if json_copy["reporting"][target_image]["recommendation"]["target"] is None:
                # There is no recommendation for image upgrade; no need to create an issue
                core.log_and_print("debug", "There is no upgrade recommendation fot image {}. Skipping Jira issue."
                                   .format(target_image))
                continue

            prettytable = exporters.create_prettytable(config_object["output"], json_sinker)

            jira_query = {
                "target_image": target_image,
                "recommendation": json_copy["reporting"][target_image]["recommendation"],
                "table": prettytable,
                "json": json_copy
            }

            result = jira_helper.search_for_issues_image(config_jira_object, jira_query)
            if result["total"] == 0:
                # If not, let's create one
                jira_helper.create_new_issue_image(config_jira_object, jira_query)
            else:
                # If it already exists, let take a note in the log and skip to the next one.
                core.log_and_print("debug", "Jira issue already exists for {}"
                                   .format(target_image))

            # We won't continue to report each vulnerability (code block B)
            # So, continue in the 'for loop' for another target image
            continue

        # Code block B: Target image is not public

        # Reporting depends on the information available in JSON
        # 1. We try to report Unanimous and Disputed findings if they were reported
        # 2. If not, we try to use "by_id", if it has been enabled

        # If you are running only one tool, all findings will be in 'unanimous findings' category.

        findings = ["unanimous_findings", "disputed_findings", "by_id"]

        for finding_list in findings:
            # 1.1. Unanimous findings
            if config_object["reporting"]["unanimous_findings"] and \
                    config_jira_object["issue_options"]["include_unanimous_findings"]:
                core.log_and_print("debug", "Checking Jira issues according to unanimous findings.")
                select_vulnerabilities(config_object, json_sinker, target_image, finding_list)
            else:
                continue

            # 1.2. Disputed findings
            if config_object["reporting"]["disputed_findings"] and \
                    config_jira_object["issue_options"]["include_disputed_findings"]:
                core.log_and_print("debug", "Checking Jira issues according to disputed findings.")
                select_vulnerabilities(config_object, json_sinker, target_image, finding_list)
            else:
                continue

            # 2. By ID
            if not config_object["reporting"]["unanimous_findings"] and \
                    not config_object["reporting"]["disputed_findings"] and finding_list == "by_id":
                core.log_and_print("debug", "Checking Jira issues according to ID.")
                select_vulnerabilities(config_object, json_sinker, target_image, finding_list)
            else:
                continue


def select_vulnerabilities(config_object, json_sinker, target_image, finding_list):
    config_jira_object = config_object["integrations"]["jira"]

    for vuln in json_sinker["reporting"][target_image][finding_list]:
        jira_query = {
            "target_image": target_image,
            "id": vuln["id"],
            "severity": vuln["severity"],
            "artifact": vuln["artifact"],
            "description": vuln["description"],
            "installed_version": vuln["installed_version"],
            "fixed_version": vuln["fixed_version"],
            "datasource": vuln["datasource"],
            "datasource_nvd": vuln["datasource_nvd"],
            "finding_type": "unanimous"
        }

        # Is there any issue already created with these params?
        result = jira_helper.search_for_issues_vuln(config_jira_object, jira_query)

        # If include_only_vulns_with_fixed_versions == False or
        # If include_only_vulns_with_fixed_versions == True and fixed_version is not null:
        if (not config_jira_object["issue_options"]["include_only_vulns_with_fixed_versions"]) or \
                (config_jira_object["issue_options"]["include_only_vulns_with_fixed_versions"] and
                 vuln["fixed_version"]):

            # Is there any issue already created with these params?
            if result["total"] == 0:
                # If not, let's create one
                jira_helper.create_new_issue_id(config_jira_object, jira_query)
            else:
                # If it already exists, let take a note in the log and skip to the next one.
                core.log_and_print("debug", "Jira issue already exists for {}, {}, {}"
                                   .format(vuln["id"], vuln["artifact"], target_image))

        else:
            # fixed_version is null:
            if result["total"] == 0:
                core.log_and_print("debug", "Jira issue skipped for {}, {}, {}"
                                   .format(vuln["id"], vuln["artifact"], target_image))
            else:
                core.log_and_print("debug", "Jira issue already exists for {}, {}, {}"
                                   .format(vuln["id"], vuln["artifact"], target_image))
