# Sinker
# Author: Marcelo Martins
# Source: https://github.com/mmartins000/sinker

import argparse
import json
import yaml
import sys
import time
import shutil
import os
import glob
import datetime
from pathlib import Path

# Pre-req
import docker
from docker import errors

# Our modules
import helpers
import parsers
import integrators
import exporters


def log_and_print(msg_loglevel, message):
    """
    Logs a message to stdout and/ot file
    :param msg_loglevel: Log level defined for that message
    :param message: The message itself
    :return: True
    """
    # Log levels to output to stdout and to logfile
    switch = {
        "debug": 0,
        "info": 1,
        "warn": 2,
        "error": 3,
        "critical": 4
    }
    # Print to stdout: if message loglevel is not debug
    switch.get(msg_loglevel) > 0 and verbose_mode and print(message)

    # Print to log: if message loglevel is in the range configured to be reported:
    if switch.get(msg_loglevel) >= switch.get(log_level, 1):
        logging_enabled and write_to_log(msg_level=msg_loglevel,
                                         log_dest=log_output,
                                         message_to_log=message)


def write_to_log(msg_level, log_dest, message_to_log):
    """
    Writes JSON dict to file.
    :param msg_level: Log level before the message
    :param log_dest: Destination where data will be written
    :param message_to_log: Text to be logged
    :return: True for success, otherwise exits with error code in case of exception
    """
    log_datetime = str(datetime.datetime.now().strftime(log_datetime_format))
    try:
        # Creates recursive path if it doesn't exist (should have been created by start_logging()
        Path(sinker_output_folder).mkdir(parents=True, exist_ok=True)
        with open(log_dest, 'a') as f:
            # If a message_to_log comes with a '\n' at the end
            message_to_log = message_to_log.strip('\n')

            if not logging_as_json:
                full_msg = str(log_datetime + log_sep + msg_level + log_sep + message_to_log + '\n')
                f.write(full_msg)
            else:
                # JSON logging is based on https://jsonlines.org/
                full_msg = {
                    "datetime": log_datetime,
                    "level": msg_level,
                    "message": message_to_log
                }
                f.write(json.dumps(full_msg) + "\n")

    except PermissionError:
        helpers.dest_not_writable(log_dest)


def start_logging(log_dest):
    """
    Removes and recreates logfile, according to config
    :param log_dest: Full path to log file
    :return: True if successful, otherwise exits with error signal
    """
    try:
        if logging_overwrite_file_if_exists:
            os.remove(log_dest)
        Path(log_dest).touch(exist_ok=True)

    except FileNotFoundError:
        Path(sinker_output_folder).mkdir(parents=True, exist_ok=True)
        Path(log_dest).touch(exist_ok=True)

    except PermissionError:
        helpers.dest_not_writable(log_dest)


def docker_save_log(str_log, output_file):
    """
    Used to save Docker process stdout to output file
    :param str_log: Docker output
    :param output_file: Destination file
    :return: True if successful, False if it could not read stdout data or write it to file
    """
    try:
        with open(output_file, 'w') as f:
            try:
                res = json.loads(str_log)
                json.dump(res, f, indent=4)
                log_and_print("debug", "File {} saved.".format(output_file))

            except json.decoder.JSONDecodeError:
                log_and_print("error", "Could not understand stdout data.".format(output_file))
                return False

    except FileNotFoundError:
        log_and_print("error", "Could not write to file {}.".format(output_file))
        return False


def convert_target_image_to_filename(target_image):
    """
    Replaces ':' for '_'. Used as helper to create filenames.
    :param target_image: Target image in format registry:repo/image:tag or image:tag
    :return: String
    """
    return str(target_image).replace(':', '_').replace('/', '_')


def run_docker_syft(target_image, sinker_output, config_syft):
    """
    Runs Docker Syft container. Called by run_scan().
    :param target_image: Container image where the apps will perform their security assessment.
    :param sinker_output: Sinker output folder
    :param config_syft: JSON object for Syft config subsection
    :return: True
    """
    if not config_syft["enabled"]:
        return

    log_and_print("info", "Running Syft on {}...".format(target_image))

    docker_image_syft = config_syft["image"]
    results_syft_filename = config_syft["output_filename"]
    output_format_syft = config_syft["output_format"]

    target_filename = convert_target_image_to_filename(target_image)

    # Used because the 'results volume' was mounted; for Docker, use '/results/[filename]'
    # More than one format is possible
    str_output_syft = ""
    full_syft_result = ""
    try:
        for i, output_format in enumerate(output_format_syft):
            # For command_to_run (docker module):
            str_output_syft = str_output_syft + \
                "-o {}=/results/{}-{} ".format(output_format_syft[i], target_filename, results_syft_filename[i])
            # To know which file should be opened for processing:
            if output_format == "spdx-json":
                full_syft_result = results_syft_filename[i]

    except IndexError:
        # If config file is wrong or the lists don't match, I'll stick to the defaults
        full_syft_result = str('sbom_syft_spdx.json')
        str_output_syft = "-o spdx-json=/results/{}-sbom_syft_spdx.json".format(target_filename)

    finally:
        if not full_syft_result:
            full_syft_result = str('sbom_syft.json')
        full_syft_result = "{}/{}-{}".format(sinker_output, target_filename, full_syft_result).replace('//', '/')

    environment_vars_syft = ["SYFT_CHECK_FOR_APP_UPDATE=false"]

    # Start Syft execution
    start = time.time()
    try:
        dc = docker.from_env()
        container_id = dc.api.create_container(
            image=docker_image_syft,
            command="{} {}".format(target_image, str_output_syft),
            volumes=['/results', '/var/run/docker.sock'],
            environment=environment_vars_syft,
            # If network_disabled=True, Syft won't work
            network_disabled=False,
            host_config=dc.api.create_host_config(binds={
                '/var/run/docker.sock': {
                    'bind': '/var/run/docker.sock',
                    'mode': 'ro',
                },
                sinker_output: {
                    'bind': '/results',
                    'mode': 'rw',
                }
            })
        )
        dc.api.start(container_id)
        dc.api.wait(container_id)
        # Not necessary, results volume mounted and used in command
        # docker_save_log(dc.api.logs(container_id).decode('utf-8'), results_syft)

    except docker.errors.ContainerError as e:
        log_and_print("error", "{}".format(e.stderr))

    else:
        end = time.time()
        total_time = str(round(end - start, 2)) + " seconds"
        str_it_took = ", it took " + total_time
        log_and_print("info", "Docker ran Syft container in {}{} and the report was saved in {}."
                      .format(target_image, str_it_took, full_syft_result))


def run_docker_grype(target_image, sinker_output, config_grype):
    """
    Runs Docker Grype container. Called by run_scan().
    :param target_image: Container image where the apps will perform their security assessment.
    :param sinker_output: Sinker output folder
    :param config_grype: Config subsection for Grype from config file
    :return: True
    """
    if not config_grype["enabled"]:
        return

    log_and_print("info", "Running Grype on {}...".format(target_image))

    docker_image_grype = config_grype["image"]
    cache_dir = config_grype["cache_dir"]
    environment_vars = config_grype["environment_vars"]
    config_file = config_grype["config_file"]
    results_grype_filename = config_grype["output_filename"]
    output_format_grype = config_grype["output_format"]

    target_filename = convert_target_image_to_filename(target_image)
    # Used because the 'results volume' was mounted
    results_volume_filename = "/results/{}".format(results_grype_filename).replace('//', '/')
    full_grype_result = str(sinker_output + "/" + target_filename + "-" + results_grype_filename).replace('//', '/')

    cache_dir_host = cache_dir["cache_dir_host"]
    cache_dir_container = cache_dir["cache_dir_container"]

    # SBOM, Syft
    str_input_syft = ""
    try:
        # We can have more than one output
        for i, value in enumerate(output_format_syft):
            if output_format_syft == "json":
                str_input_syft = results_syft_filename[i]

    except IndexError:
        # If config file is wrong or the lists don't match, I'll stick to my default
        str_input_syft = "sbom_syft.json"

    finally:
        # If still blank, there was no 'json' value in output_format_syft:
        if not str_input_syft:
            str_input_syft = "sbom_syft.json"

    target_filename = convert_target_image_to_filename(target_image)
    str_input_syft = "{}/{}-{}".format("/results", target_filename, str_input_syft)

    # Config file (contains rule exclusions):
    str_config_file = ""
    if Path(config_file).is_file():
        # Starts with a space; check the formatting of 'command_to_run'
        str_config_file = " -c {}".format(config_file)

    # If Syft wasn't executed, Grype can do its job
    if Path(str_input_syft.split('/')[1]).is_file():
        # With Syft input we don't need to inform target image
        command_to_run = "sbom:{} -o {}{}"\
            .format(str_input_syft, output_format_grype, str_config_file)\
            .replace('//', '/')
    else:
        # No Syft, must inform target image

        # Flag --add-cpes-if-none: https://github.com/anchore/grype/#supported-sources
        # Note: This flag didn't work in version: 0.33.1.
        # Container execution returns: "unknown flag: --add-cpes-if-none". Removed from 'command_to_run'

        command_to_run = "{} -o {}{}"\
            .format(target_image, output_format_grype, str_config_file)\
            .replace('//', '/')

    # Before starting scan, locate vulnerability DB (cache) or exit with error code
    locate_vulndb(cache_dir_host)

    # By default, Grype tries to connect to https://toolbox-data.anchore.io/grype/releases/latest/VERSION
    # to check for database updates.
    # To avoid this connection, the next two env vars must be passed to Grype durinf execution:
    # "GRYPE_CHECK_FOR_APP_UPDATE=false",
    # "GRYPE_DB_AUTO_UPDATE=false"
    # If not present and network_disabled=True, Grype won't work
    environment_vars.append("GRYPE_CHECK_FOR_APP_UPDATE=false")
    environment_vars.append("GRYPE_DB_AUTO_UPDATE=false")

    # Start scan
    start = time.time()
    try:
        dc = docker.from_env()
        container_id = dc.api.create_container(
            image=docker_image_grype,
            command=command_to_run,
            environment=environment_vars,
            network_disabled=True,
            volumes=[cache_dir_container, '/var/run/docker.sock', '/results'],
            host_config=dc.api.create_host_config(binds={
                cache_dir_host: {
                    'bind': cache_dir_container,
                    'mode': 'rw',
                },
                '/var/run/docker.sock': {
                    'bind': '/var/run/docker.sock',
                    'mode': 'ro',
                },
                sinker_output: {
                    'bind': '/results',
                    'mode': 'rw',
                }
            })
        )
        dc.api.start(container_id)
        dc.api.wait(container_id)
        docker_save_log(dc.api.logs(container_id).decode('utf-8'), full_grype_result)

    except docker.errors.ContainerError as e:
        log_and_print("error", "{}".format(e.stderr))

    else:
        end = time.time()
        total_time = str(round(end - start, 2)) + " seconds"
        str_it_took = ", it took " + total_time
        log_and_print("info", "Docker ran Grype container in {}{} and the report was saved in {}."
                      .format(target_image, str_it_took, full_grype_result))

        parsers.process_grype(parsers.load_from_json(full_grype_result), full_grype_result, target_image, total_time)


def run_docker_trivy(target_image, sinker_output, config_trivy):
    """
    Runs Docker Trivy container. Called by run_scan().
    :param target_image: Container image where the apps will perform their security assessment.
    :param sinker_output: Sinker output folder
    :param config_trivy: Config section for Trivy from config file
    :return: True
    """
    if not config_trivy["enabled"]:
        return

    log_and_print("info", "Running Trivy on {}...".format(target_image))

    docker_image_trivy = config_trivy["image"]
    cache_dir = config_trivy["cache_dir"]
    results_trivy_filename = config_trivy["output_filename"]
    output_format_trivy = config_trivy["output_format"]
    policy = config_trivy["policy"]

    # Trivy can save in different formats and the stdout output is different from JSON object
    # Output will be saved with filename 'results-trivy.json' (if output-format is JSON)
    # Because Trivy is doing the output, I need to mount another volume for default results folder, otherwise
    # there will be no output
    # Ref: https://aquasecurity.github.io/trivy/v0.24.1/getting-started/cli/config/

    target_filename = convert_target_image_to_filename(target_image)
    # Used because the 'results volume' was mounted
    results_volume_filename = "/results/{}-{}".format(target_filename, results_trivy_filename).replace('//', '/')
    full_trivy_result = str(sinker_output + "/" + target_filename + "-" + results_trivy_filename).replace('//', '/')

    cache_dir_host = cache_dir["cache_dir_host"]
    cache_dir_container = cache_dir["cache_dir_container"]

    # Flag --policy can be used for policy exceptions
    # Trivy accepts multiple uses of --policy; multiple directories can be specified, one in each use
    policies = ""
    if len(policy) > 0:
        # Starts with a space char; check formatting below
        policies = ' --policy '.join(policy_dir for policy_dir in policy)

    # Flags --skip-update --skip-policy-update:
    # Decided to leave it 'Air-Gapped' here and the updated done at update_trivy_vulndb()
    # https://aquasecurity.github.io/trivy/v0.24.4/advanced/air-gap/
    # Update: Flags --skip-policy-update wasn't recognized
    command_to_run = "--cache-dir {} image --skip-update --format {} --output {}{} {}"\
        .format(cache_dir_container, output_format_trivy, results_volume_filename, policies, target_image)

    # Before starting scan, locate vulnerability DB (cache) or exit with error code
    locate_vulndb(cache_dir_host)

    start = time.time()
    try:
        dc = docker.from_env()
        container_id = dc.api.create_container(
            image=docker_image_trivy,
            command=command_to_run,
            volumes=[cache_dir_container, '/results', '/var/run/docker.sock'],
            network_disabled=True,
            host_config=dc.api.create_host_config(binds={
                cache_dir_host: {
                    'bind': cache_dir_container,
                    'mode': 'rw',
                },
                '/var/run/docker.sock': {
                    'bind': '/var/run/docker.sock',
                    'mode': 'ro',
                },
                sinker_output: {
                    'bind': '/results',
                    'mode': 'rw',
                }
            })
        )
        dc.api.start(container_id)
        dc.api.wait(container_id)
        # Not necessary, results volume mounted and used in command
        # docker_save_log(dc.api.logs(container_id).decode('utf-8'), results_trivy)

    except docker.errors.ContainerError as e:
        log_and_print("error", "{}".format(e.stderr))

    except Exception as e:
        log_and_print("error", "{}".format(e.args))

    else:
        end = time.time()
        total_time = str(round(end - start, 2)) + " seconds"
        str_it_took = ", it took " + total_time
        log_and_print("info", "Docker ran Trivy container in {}{} and the report was saved in {}."
                      .format(target_image, str_it_took, full_trivy_result))

        parsers.process_trivy(parsers.load_from_json(full_trivy_result), full_trivy_result, target_image, total_time)


def run_docker_snyk(target_image, sinker_output, config_snyk):
    """
    Runs Docker Snyk container. Called by run_scan().
    :param target_image: Container image where the apps will perform their security assessment.
    :param sinker_output: Sinker output folder
    :param config_snyk: Config section for Snyk from config file
    :return: True
    """
    if not config_snyk["enabled"]:
        return

    if not parsers.check_image_in_public_registry(target_image):
        log_and_print("error", "Aborting Snyk execution on {}. Container image isn't public.".format(target_image))
        return

    log_and_print("info", "Running Snyk on {}...".format(target_image))

    docker_image_snyk = config_snyk["image"]
    # cache_dir = config_snyk["cache_dir"]
    environment_vars = config_snyk["environment_vars"]
    results_snyk_filename = config_snyk["output_filename"]
    output_format_snyk = config_snyk["output_format"]
    # policy = config_snyk["policy"]

    # Ref: https://docs.snyk.io/snyk-cli/cli-reference

    target_filename = convert_target_image_to_filename(target_image)
    # Used because the 'results volume' was mounted
    results_volume_filename = "/results/{}-{}".format(target_filename, results_snyk_filename).replace('//', '/')
    full_snyk_result = str(sinker_output + "/" + target_filename + "-" + results_snyk_filename).replace('//', '/')

    # Snyk won't store a local database in a mounted volume
    # cache_dir_host = cache_dir["cache_dir_host"]
    # cache_dir_container = cache_dir["cache_dir_container"]

    command_to_run = "snyk test --{} --json-file-output={} --docker {}"\
        .format(output_format_snyk, results_volume_filename, target_image)

    # Snyk depends on Internet access; code below won't work for Snyk
    # Before starting scan, locate vulnerability DB (cache) or exit with error code
    # locate_vulndb(cache_dir_host)

    start = time.time()
    try:
        dc = docker.from_env()
        container_id = dc.api.create_container(
            image=docker_image_snyk,
            command=command_to_run,
            environment=environment_vars,
            # If network_disabled=True, Snyk won't work
            network_disabled=False,
            volumes=['/results', '/var/run/docker.sock'],
            # volumes=[cache_dir_container, '/results', '/var/run/docker.sock'],
            host_config=dc.api.create_host_config(binds={
                # cache_dir_host: {
                #     'bind': cache_dir_container,
                #     'mode': 'rw',
                # },
                '/var/run/docker.sock': {
                    'bind': '/var/run/docker.sock',
                    'mode': 'ro',
                },
                sinker_output: {
                    'bind': '/results',
                    'mode': 'rw',
                }
            })
        )
        dc.api.start(container_id)
        dc.api.wait(container_id)
        # Not necessary, results volume mounted and used in command
        # docker_save_log(dc.api.logs(container_id).decode('utf-8'), results_snyk)

    except docker.errors.ContainerError as e:
        log_and_print("error", "{}".format(e.stderr))

    except Exception as e:
        log_and_print("error", "{}".format(e.args))

    else:
        end = time.time()
        total_time = str(round(end - start, 2)) + " seconds"
        str_it_took = ", it took " + total_time
        log_and_print("info", "Docker ran Snyk container in {}{} and the report was saved in {}."
                      .format(target_image, str_it_took, full_snyk_result))

        parsers.process_snyk(parsers.load_from_json(full_snyk_result), full_snyk_result, target_image, total_time)
        # Parse Snyk recommendation for image upgrade
        parsers.process_snyk_image_rec(parsers.load_from_json(full_snyk_result), target_image)


def run_scanners(config_object):
    """
    Calls Docker functions. Called by main().
    :return: True if successful; False if PermissionError exception raised
    """
    get_scanner_versions(config_object=config_object)
    targets_object = get_targets(targets_file)

    sinker_output_folder = config["output"]["sinker_output_folder"]

    log_and_print("info", "Starting container image scans.")

    for target in targets_object["images"]:
        log_and_print("info", "Scanning target {}.".format(target))

        # Create output directory
        try:
            Path(sinker_output_folder).mkdir(parents=True, exist_ok=True)

        except FileExistsError:
            # Should not be raised due to 'exist_ok=True'
            log_and_print("debug", "Folder {} already exists.".format(sinker_output_folder))

        except PermissionError:
            helpers.dest_not_writable(sinker_output_folder)

        run_docker_syft(target, sinker_output_folder, config_object["sbom"]["syft"])
        run_docker_snyk(target, sinker_output_folder, config_object["scanners"]["snyk"])
        run_docker_grype(target, sinker_output_folder, config_object["scanners"]["grype"])
        run_docker_trivy(target, sinker_output_folder, config_object["scanners"]["trivy"])

        log_and_print("info", "Finished scanning container image {}.".format(target))

    log_and_print("info", "Finished scanning all targets.")


def locate_vulndb(cache_dir_host):
    """
    If flag --no-update is used and there is no vulnerability DB cache, the apps won't run
    :param cache_dir_host: Directory where tool should locate their vulnerability DB cache
    :return: True if successful, exits with error code if no cache found
    """
    try:
        if Path(cache_dir_host).is_dir():
            dir_size = sum(f.stat().st_size for f in Path(cache_dir_host).glob('**/*') if f.is_file())
            # If dir exists, may be empty; I'm considering at least 10000 bytes of size to be valid
            if dir_size > 10000:
                return True
            else:
                helpers.missing_vulndb(cache_dir_host)
        else:
            helpers.missing_vulndb(cache_dir_host)

    except KeyError:
        helpers.missing_vulndb(cache_dir_host)


def update_vulnerability_databases(config_object):
    update_trivy_vulndb(config_trivy=config_object["scanners"]["trivy"])
    update_grype_vulndb(config_grype=config_object["scanners"]["grype"])


def update_trivy_vulndb(config_trivy):
    """
    Runs Docker to update Trivy vulnerability database. Called by main().
    :return: Return of function update_vulndb()
    """
    if not config_trivy["enabled"] or args.noUpdate:
        return

    log_and_print("info", "Updating vulnerability database for Trivy...")

    container_image = config_trivy["image"]
    cache_dir = config_trivy["cache_dir"]

    # Create directories for cache
    cache_dir_host = cache_dir["cache_dir_host"]
    cache_dir_container = cache_dir["cache_dir_container"]
    try:
        Path(cache_dir_host).mkdir(parents=True, exist_ok=True)
        log_and_print("debug", "Directory {} created.".format(cache_dir_host))

    except FileExistsError:
        # Should not be raised because 'exist_ok=True'
        pass

    except PermissionError:
        helpers.dest_not_writable(cache_dir_host)

    command_to_run = "--cache-dir {} image --download-db-only".format(cache_dir_container)
    return update_vulndb(container_image=container_image,
                         command_to_run=command_to_run,
                         cache_dir=cache_dir)


def update_grype_vulndb(config_grype):
    """
    Runs Docker to update Grype vulnerability database. Called by main().
    :return: String with version
    """
    if not config_grype["enabled"] or args.noUpdate:
        return

    container_image = config_grype["image"]
    cache_dir = config_grype["cache_dir"]
    environment_vars = config_grype["environment_vars"]

    # Create directories for cache
    cache_dir_host = cache_dir["cache_dir_host"]
    # cache_dir_container = cache_dir["cache_dir_container"]
    try:
        Path(cache_dir_host + "/3").mkdir(parents=True, exist_ok=True)
        log_and_print("debug", "Directory {} created.".format(cache_dir_host + "/3"))

    except FileExistsError:
        # Should not be raised because 'exist_ok=True'
        pass

    except PermissionError:
        helpers.dest_not_writable(cache_dir_host)

    # Run 'grype db list -o raw' to get the list of vulnerability DBs
    result_db_list = update_vulndb(cache_dir=cache_dir,
                                   command_to_run='db list -o raw',
                                   container_image=container_image)
    docker_save_log(result_db_list, cache_dir_host + '/' + str(environment_vars[0]).rsplit('/', 1)[1])

    # Run 'grype db check' to check if there is an update available
    result_db_check = update_vulndb(cache_dir=cache_dir,
                                    command_to_run='db check',
                                    container_image=container_image,
                                    environment_vars=environment_vars)

    # Run 'grype db update' to perform the update
    if 'No update available' not in result_db_check:
        log_and_print("info", "Updating vulnerability database for Grype...")
        update_vulndb(cache_dir=cache_dir,
                      command_to_run='db update',
                      container_image=container_image,
                      environment_vars=environment_vars)
    else:
        log_and_print("info", "Grype vulnerability database is already up-to-date.")


def update_vulndb(container_image, command_to_run, cache_dir, environment_vars=""):
    """
    Base function that runs Docker to update app vulnerability database.
    Called by update_vulndb_grype() and update_vulndb_trivy().
    :param container_image: The image that will be executed to update the database
    :param command_to_run: Command to update the database
    :param cache_dir: Directory where vulnerability database will be saved (cached)
    :param environment_vars: Environment variables used by Grype to update the database
    :return: stdout
    """
    dc = docker.from_env()

    # if args.forceDockerPull == False (docker binary --pull "missing" flag behaviour)
    if not args.forceDockerPull:
        try:
            dc.images.get(container_image)

        except docker.errors.ImageNotFound:
            dc.images.pull(container_image)

    else:  # if args.forceDockerPull == True (docker binary --pull "always" flag behaviour)
        try:
            dc.images.pull(container_image)
            log_and_print("debug", "Downloaded container image {}.".format(container_image))

        except docker.errors.ImageNotFound:
            log_and_print("error", "Could not find Docker image {}".format(container_image))

    try:
        cache_dir_host = cache_dir["cache_dir_host"]
        cache_dir_container = cache_dir["cache_dir_container"]

        container_id = dc.api.create_container(
            image=container_image,
            command=command_to_run,
            network_disabled=False,
            volumes=[cache_dir_host, '/var/run/docker.sock'],
            environment=environment_vars,
            host_config=dc.api.create_host_config(binds={
                cache_dir_host: {
                    'bind': cache_dir_container,
                    'mode': 'rw',
                },
                '/var/run/docker.sock': {
                    'bind': '/var/run/docker.sock',
                    'mode': 'ro',
                }
            })
        )
        dc.api.start(container_id)
        dc.api.wait(container_id)
        return dc.api.logs(container_id).decode('utf-8')

    except docker.errors.ContainerError as e:
        log_and_print("error", "{}".format(e.stderr))


def get_scanner_versions(config_object):
    """
    Run scanners once, store their version and use many times to fill the reports (parsers module)
    :param config_object: Config JSON object
    :return: True
    """
    global version_syft, version_snyk, version_trivy
    version_syft = get_version_syft(config_object)
    version_snyk = get_version_snyk(config_object)
    version_trivy = get_version_trivy(config_object)
    # Grype version comes in the JSON output


def get_version_trivy(config_object):
    """
    Runs Docker to get Trivy version. Trivy JSON output doesn't contain the executable version.
    Called by process_trivy().
    :return: String with version
    """
    # Trivy outputs version in stdout as: "Version: vn.n.n"
    if not args.skipTrivy:
        return get_version(container_image=config_object["scanners"]["trivy"]["image"],
                           command_to_run='--version').split(" ")[1]


def get_version_snyk(config_object):
    """
    Runs Docker to get Snyk version. Snyk JSON output doesn't contain the executable version.
    Called by process_snyk().
    :return: String with version
    """
    # Snyk outputs version in stdout as: "n.n.n (standalone)"
    if not args.skipSnyk:
        return get_version(container_image=config_object["scanners"]["snyk"]["image"],
                           command_to_run='snyk --version')


def get_version_syft(config_object):
    """
    Runs Docker to get Syft version. Not all Syft JSON output contain the executable version.
    Called by process_syft().
    :return: String with version
    """
    # Syft outputs version in stdout as: "syft n.n.n"
    if not args.skipSyft:
        return get_version(container_image=config_object["sbom"]["syft"]["image"],
                           command_to_run='--version').split(" ")[1]


def get_version(container_image, command_to_run):
    """
    Runs Docker to get container image version.
    Called by get_version_snyk(), get_version_syft() and get_version_trivy().
    :return: String containing Container version or "None"
    """
    dc = docker.from_env()

    # No need to pull images if this function is running after docker_pull_scanner_images() in main()
    # docker_pull_image(container_image, args.forceDockerPull)
    try:
        ctn = dc.containers.run(image=container_image,
                                command=command_to_run,
                                network_disabled=True,
                                remove=True, tty=False, detach=False)
        container_version = ctn.decode("utf-8").replace('\n', '')

    except docker.errors.ContainerError:
        container_version = "None"

    return container_version


def docker_pull_target_images(targets_object, force_docker_pull):
    """
    Pulls the target images described in targets file
    docker.containers.run() and docker.api.create_container() don't include a --pull flag
    :param targets_object: JSON object for targets loaded from file
    :param force_docker_pull: If Docker should always download an image or not.
    :return: True if succeeded, False if exception raised
    """
    try:
        for target in targets_object["images"]:
            docker_pull_image(target, force_docker_pull)
        return True

    except docker.errors.ImageNotFound:
        return False

    except docker.errors.APIError:
        return False


def docker_pull_scanner_images(config_object, force_docker_pull):
    not args.skipGrype and docker_pull_image(config_object["scanners"]["grype"]["image"], force_docker_pull)
    not args.skipTrivy and docker_pull_image(config_object["scanners"]["trivy"]["image"], force_docker_pull)
    not args.skipSnyk and docker_pull_image(config_object["scanners"]["snyk"]["image"], force_docker_pull)
    not args.skipSyft and docker_pull_image(config_object["sbom"]["syft"]["image"], force_docker_pull)


def docker_pull_image(image_name, force_docker_pull):
    """
    Pulls container images.
    This is not really necessary. 'Docker run' can pull the images itself. Reason is:
    docker.containers.run() and docker.api.create_container() don't include a --pull flag
    Called by docker_pull_scanner_images() and docker_pull_target_images()
    :param image_name: Container image to be downloaded, format: 'repo/image:tag'
    :param force_docker_pull: If Docker should 'always' download an image, if it should download only
    when it's 'missing' or if it should 'never' download.
    :return: True if succeeded, False if exception raised
    """
    dc = docker.from_env()
    found_image = False
    if force_docker_pull == "missing" or force_docker_pull == "never":
        # We will check if we have the image because --pull "missing"
        for image in dc.images.list(all=True):
            if image.attrs['RepoTags']:   # Reason: the list contained empty values; bug?
                if image.attrs['RepoTags'][0] == image_name:
                    found_image = True
                    log_and_print("info", "Docker image {} found and will not be downloaded.".format(image_name))
                    # Function ran looking for one single image. If we found it, we can leave the loop.
                    break
        if force_docker_pull == "never" and not found_image:
            log_and_print("critical",
                          "Docker image {} not found and will not be downloaded due to --force-docker-pull={}."
                          .format(image_name, force_docker_pull))
            sys.exit(helpers.EXIT_INVALID_TARGETS)

    if force_docker_pull == "always" or (force_docker_pull == "missing" and not found_image):
        log_and_print("info", "Downloading Docker image for {}.".format(image_name))
        try:
            dc.api.pull(image_name)

        except docker.errors.APIError as e:
            log_and_print("error", "{}".format(e.args))
            return False

        else:
            log_and_print("info", "Docker just downloaded image {}.".format(image_name))


def remove_target_images(targets_object):
    """
    Removes target images if they are described in target file
    Called by clean_up()
    :return: True
    """
    if not bool_remove_target_images_after_scan:
        return

    dc = docker.from_env()
    for image in dc.images.list(all=True):
        # for target in targets_object["images"]:
        if image.attrs['RepoTags'][0]:  # Reason: the list contained empty values; bug?
            if image.attrs['RepoTags'][0] in targets_object["images"]:
                try:
                    dc.images.remove(image.id)

                except docker.errors.ContainerError as e:
                    log_and_print("error", "{}".format(e.stderr))

                except docker.errors.ImageNotFound as e:
                    log_and_print("error", "{}".format(e.args))

                else:
                    log_and_print("debug", "Removed image {}, image.short_id={}"
                                  .format(image.attrs['RepoTags'][0].split("@")[0], image.short_id))


def prune_scanner_images(config_object):
    """
    Prunes untagged scanner images described in the config file.
    Called by main()
    :param config_object: Config JSON object from config file.
    :return: True
    """
    if not config_object["settings"]["prune_untagged_images_after_scan"]:
        return

    dc = docker.from_env()

    # For untagged image in the list
    for image in dc.images.list(all=True, filters={'dangling': True}):
        # For every scanner in config file
        for scanner in config_object["scanners"]:
            value = config_object["scanners"][scanner]["image"]
            docker_remove_image(image, value)


def prune_scanner_containers(config_object):
    """
    Prunes containers of scanner and sbom tools defined in config file.
    Called by main()
    :param config_object: Config JSON object from config file.
    :return: True
    """
    if not config["settings"]["prune_containers_after_scan"]:
        return

    filters = []
    for scanner in config_object["scanners"]:
        filters.append({'status': 'exited', 'ancestor': config_object["scanners"][scanner]["image"].split(":")[0]})
        # Removal of Snyk container without :docker tag didn't work.
        filters.append({'status': 'exited', 'ancestor': config_object["scanners"]["snyk"]["image"]})
    for sbom in config_object["sbom"]:
        filters.append({'status': 'exited', 'ancestor': config_object["sbom"][sbom]["image"].split(":")[0]})

    dc = docker.from_env()
    for filter_dict in filters:
        for container in dc.containers.list(all=True, filters=filter_dict):
            try:
                container.remove(v=True)

            except docker.errors.ContainerError as e:
                log_and_print("error", "{}".format(e.stderr))

            else:
                # container.remove() does not return anything
                log_and_print("debug", "Removed {}, container.short_id={}"
                              .format(container.attrs['Config']['Image'], container.short_id))


def remove_scanner_images(config_object):
    """
    Removes downloaded scanner images of tools described in the config file.
    :param config_object: Config JSON object from config file.
    :return: True
    """
    if not config_object["settings"]["remove_scanner_images_after_scan"]:
        return

    # Created so I can iterate through 2 lists in a single for loop
    item_list = [config_object["scanners"].items(), config_object["sbom"].items()]

    dc = docker.from_env()
    # For each image downloaded:
    for image in dc.images.list(all=True):
        # For each item (scanner or sbom) in config file:
        for key, value in item_list:
            docker_remove_image(image, value)


def docker_remove_image(image, value):
    """
    Base function used by remove_scanner_images() and prune_scanner_images()
    :param image:
    :param value:
    :return: True; False if exception raised
    """
    dc = docker.from_env()

    if image is not None and len(image.attrs['RepoDigests']) > 0:
        if image.attrs['RepoDigests'][0].split("@")[0] in value:
            try:
                dc.images.remove(image.id)

            except docker.errors.ContainerError as e:
                log_and_print("error", "{}".format(e.stderr))

            except docker.errors.ImageNotFound as e:
                log_and_print("error", "{}".format(e.args))

            except docker.errors.APIError as e:
                log_and_print("error", "{}".format(e.args))

            else:
                # images.remove() does not return anything
                log_and_print("debug", "Removed {}, image.short_id={}"
                              .format(image.attrs['Config']['Image'], image.short_id))
                return True

    return False


def docker_login(config_object):
    """
    Authenticates with docker registry, using default or alternate 'dockercfg_path' with credentials.
    :param config_object: Config JSON object from config file
    :return: True if 'docker login' is successful, exits with error in case of exception
    """
    dockercfg_path = config_object["authentication"]["dockercfg_path"]
    if dockercfg_path:
        dc = docker.from_env()
        try:
            res = dc.login(dockercfg_path=dockercfg_path)
            print(res)
        except docker.errors.APIError:
            log_and_print("critical", "Could not login using {} credentials.".format(dockercfg_path))
            critical_cleanup()
            sys.exit(helpers.EXIT_INVALID_LOGIN)
        else:
            log_and_print("debug", "Logged in using {} credentials.".format(dockercfg_path))
            return True


def get_targets(target_file):
    """
    Reads targets file specified in sinker.json into a JSON object
    :param target_file: Directory, YAML filename, JSON filename
    :return: True if successfully loaded the file; False in case of exception
    """
    target_list = []

    def read_yaml_file_into_list(yaml_file):
        with open(yaml_file) as f:
            for doc in yaml.safe_load_all(f):
                image_list = helpers.find_values('image', json.dumps(doc))
                for image in image_list:
                    target_list.append(image)

    # If target_file is actually a directory, look for YAML files:
    try:
        target_file = glob.glob(target_file)[0]
        if Path(target_file).is_dir():
            yaml_files = \
                glob.glob(os.path.join(targets_file, '*.yaml')) + glob.glob(os.path.join(targets_file, '*.yml'))
            for yaml_file in yaml_files:
                read_yaml_file_into_list(yaml_file)

            target_list.sort()
            target_list = list(set(target_list))
            json_list = {
                "images": target_list
            }
            return json_list

    except (IndexError, FileNotFoundError):
        # Not a directory or not expandable
        pass

    except yaml.YAMLError:
        # Not YAML
        pass

    # YAML file
    try:
        target_file = glob.glob(target_file)[0]
        if Path(target_file).is_file() and (target_file.endswith('.yaml') or target_file.endswith('.yml')):
            read_yaml_file_into_list(target_file)

            target_list.sort()
            target_list = list(set(target_list))
            json_list = {
                "images": target_list
            }
            return json_list

    except yaml.YAMLError:
        # Not YAML
        pass

    except IndexError:
        # Not expandable
        pass

    # JSON file with targets list
    try:
        target_file = glob.glob(target_file)[0]
        if Path(target_file).is_file() and target_file.endswith('.json'):
            return parsers.load_from_json(target_file)

    except (FileNotFoundError, PermissionError) as e:
        log_and_print("error", "{}".format(e.stderr))
        return False

    except IndexError:
        # Not expandable
        pass

    # Check if the argument entered in --targets is an image name.
    dc = docker.from_env()
    try:
        # 'ubuntu' is the first result when I search for 'debian'
        res = dc.images.search(str(target_file).split(':')[0], limit=5)
        for t in res:
            if t["name"] == str(target_file).split(':')[0]:
                json_list = {
                    "images": [target_file]
                }
                return json_list

    except docker.errors.APIError as e:
        log_and_print("error", "{}".format(e.args))
        return False

    except IndexError:
        log_and_print("critical", "Could not find an image named as '{}'".format(target_file))
        sys.exit(helpers.EXIT_INVALID_TARGETS)

    else:
        # Could not understand the target; will leave to docker to figure it out
        json_list = {
            "images": [target_file]
        }
        return json_list


def get_scanners(config_object):
    scanners_list = []
    try:
        for scanner in config_object["scanners"]:
            if config_object["scanners"][scanner]["enabled"]:
                scanners_list.append(str(scanner).capitalize())

    except KeyError:
        log_and_print("critical", "Could not understand config file.")
        sys.exit(helpers.EXIT_INVALID_CONFIG)

    return scanners_list


def prepare_signal_stats(json_object):
    """
    Reads json_sinker reporting section, calculates findings by severity
    :param json_object: JSON object for json_sinker
    :return: dict containing vulnerabilities per severity
    """
    int_critical, int_high, int_medium, int_low = 0, 0, 0, 0
    for target in json_object["reporting"]:
        int_critical += int(json_object["reporting"][target]["summary"]["findings_by_severity"]["critical"])
        int_high += int(json_object["reporting"][target]["summary"]["findings_by_severity"]["high"])
        int_medium += int(json_object["reporting"][target]["summary"]["findings_by_severity"]["medium"])
        int_low += int(json_object["reporting"][target]["summary"]["findings_by_severity"]["low"])

    signal_stats = {
        "critical": int_critical,
        "high": int_high,
        "medium": int_medium,
        "low": int_low
    }

    return signal_stats


def choose_exit_signal(json_object=None):
    """
    Chooses the exit signal when used in CI.
    Makes more sense when only one image is assessed in each run, because many images may be assessed but
    only one signal will be returned.
    :param json_object: JSON object containing the summary for each target image
    :return: exit signal, depending on config and vulnerabilities found
    """
    if json_object is not None:
        int_critical = json_object["critical"]
        int_high = json_object["high"]
        int_medium = json_object["medium"]
        int_low = json_object["low"]

        if bool_fail_on_critical and int_critical > 0:
            log_and_print("debug", "Exiting with signal EXIT_FAIL_CRITICAL: {}".format(EXIT_FAIL_CRITICAL))
            sys.exit(EXIT_FAIL_CRITICAL)
        elif bool_fail_on_high and (int_critical > 0 or int_high > 0):
            log_and_print("debug", "Exiting with signal EXIT_FAIL_HIGH: {}".format(EXIT_FAIL_HIGH))
            sys.exit(EXIT_FAIL_HIGH)
        elif bool_fail_on_medium and (int_critical > 0 or int_high > 0 or int_medium > 0):
            log_and_print("debug", "Exiting with signal EXIT_FAIL_MEDIUM: {}".format(EXIT_FAIL_MEDIUM))
            sys.exit(EXIT_FAIL_MEDIUM)
        elif bool_fail_on_low and (int_critical > 0 or int_high > 0 or int_medium > 0 or int_low > 0):
            log_and_print("debug", "Exiting with signal EXIT_FAIL_LOW: {}".format(EXIT_FAIL_LOW))
            sys.exit(EXIT_FAIL_LOW)

    log_and_print("debug", "Exiting with signal EXIT_OK: {}".format(EXIT_OK))
    sys.exit(EXIT_OK)


def critical_cleanup():
    """
    Calls prune functions in case of critical errors to avoid leaving containers behind.
    :return: True
    """
    prune_scanner_containers(config)
    prune_scanner_images(config)


def clean_up():
    """
    Removes downloaded Docker scanner and target images if config allows.
    Called by main().
    :return: True
    """
    if bool_remove_target_images_after_scan or bool_remove_scanner_images_after_scan:
        log_and_print("info", "Starting clean up...")

        # Remove Docker images: $ docker rmi [image]
        # Remove the targets to clean up space after assessment (user decision)
        bool_remove_target_images_after_scan and remove_target_images(get_targets(targets_file))
        # Remove scanner images if they are not frequently used (user decision)
        bool_remove_scanner_images_after_scan and remove_scanner_images(config)
    else:
        log_and_print("debug", "No clean up to do.")

    # This message won't go into the log
    args.verbose and print("Done.\n")
    return True     # Do not remove


def remove_cache_directories(config_object):
    """
    Removes all cache directories for vulnerability DBs
    :param config_object: JSON config object loaded from file
    :return: True
    """
    for scanner in config_object["scanners"]:
        cache_dir_host = config_object["scanners"][scanner]["cache_dir"]["cache_dir_host"]
        # First, we verify len is > 4, to avoid mistakes like /, /bin, /dev, /etc, /opt, /sbin, /tmp, /usr, /var
        cache_dir_to_remove = cache_dir_host.split(':')[0]
        if len(cache_dir_to_remove) > 4:
            # Erase Vulnerability DBs
            try:
                shutil.rmtree(cache_dir_to_remove, ignore_errors=True)
                log_and_print("debug", "Cache directory removed: {}".format(cache_dir_to_remove))

            except shutil.ExecError:
                log_and_print("debug", "Could not remove: {}".format(cache_dir_to_remove))


def fresh_start():
    """
    Returns the system back to where its initial state, but it won't erase report files and folders.
    Depends on config file to locate Vulnerability DBs.
    :return: True
    """
    start_logging(log_dest=config["logging"]["logging_file"])
    helpers.print_version()
    prune_scanner_containers(config)
    prune_scanner_images(config)
    remove_target_images(get_targets(targets_file))
    remove_scanner_images(config)
    remove_cache_directories(config)
    choose_exit_signal()


def process_json(json_object):
    exporters.export_prettytable(config["output"], exporters.create_prettytable(config["output"], json_object))
    integrators.send_to_integrations(config, json_object)


def print_summary(scanners, targets):
    scanners_list = ", ".join(scanners)
    targets_list = ", ".join(targets["images"])
    log_and_print("info", "Summary: Run {} in {}".format(scanners_list, targets_list))


def main():
    global json_sinker
    # Preparation
    start_logging(log_dest=config["logging"]["logging_file"])
    helpers.sanity_checks()
    print_summary(scanners=get_scanners(config), targets=get_targets(targets_file))
    json_sinker = parsers.create_json_structure()
    # Input
    docker_login(config_object=config)
    docker_pull_target_images(targets_object=get_targets(targets_file), force_docker_pull=args.forceDockerPull)
    docker_pull_scanner_images(config_object=config, force_docker_pull=args.forceDockerPull)
    update_vulnerability_databases(config)
    # Core
    run_scanners(config)
    # Output
    parsers.summarise_stats(json_sinker)
    parsers.write_json_to_file(json_sinker, config["output"]["sinker_results_file"])
    # exporters.create_prettytable(config["output"], json_sinker)
    exporters.export_prettytable(config["output"], exporters.create_prettytable(config["output"], json_sinker))
    integrators.send_to_integrations(config, json_sinker)
    # Closing
    prune_scanner_containers(config)  # Containers will be removed after assessment
    prune_scanner_images(config)      # Remove untagged images, already replaced by newer versions
    clean_up()                        # Calls remove_target_images() and remove_scanner_images()
    choose_exit_signal(prepare_signal_stats(json_sinker))


# Main scope: Argument Parser
parser = argparse.ArgumentParser()
parser.add_argument("--version", help="Print current version and exit", dest='version', action='store_true')
parser.add_argument("--config", help="Config file", dest='config', default="sinker.json")
parser.add_argument("-v", "--verbose", help="Verbose mode", dest='verbose', action='store_true')
parser.add_argument("-i", "--ignore-root", help="Ignore being executed as root", dest='ignoreRoot', action='store_true')
parser.add_argument("--skip-syft", help="Skip Syft execution", dest='skipSyft', action='store_true')
parser.add_argument("-g", "--skip-grype", help="Skip Grype execution", dest='skipGrype', action='store_true')
parser.add_argument("-t", "--skip-trivy", help="Skip Trivy execution", dest='skipTrivy', action='store_true')
parser.add_argument("-s", "--skip-snyk", help="Skip Snyk execution", dest='skipSnyk', action='store_true')
parser.add_argument("--force-docker-pull", help="Configure when Docker should pull the image. Default: missing",
                    dest='forceDockerPull', default="missing")
parser.add_argument("-o", "--output", help="Override output_folder parameter in config file", dest='output')
parser.add_argument("--targets", help="Override targets file parameter in config file", dest='targets')
parser.add_argument("--no-update", help="Do not update vulnerability DBs", dest='noUpdate', action='store_true')
parser.add_argument("--only-updates", help="Update vulnerability DBs and exit", dest='onlyUpdates', action='store_true')
parser.add_argument("--fresh-start", help="Erase images and vulnerability DBs", dest='freshStart', action='store_true')
parser.add_argument("--only-cleanup", help="Execute a clean up and exit", dest='onlyCleanup', action='store_true')
parser.add_argument("--only-process-json", help="Skip scanners and process a previously generated JSON",
                    dest='processJSON')
fail_group = parser.add_mutually_exclusive_group()
fail_group.add_argument("--fail-on-critical",
                        help="Exit with failed signal if critical severity vulnerabilities are found",
                        dest='failCritical', action='store_true')
fail_group.add_argument("--fail-on-high", help="Exit with failed signal if high severity vulnerabilities are found",
                        dest='failHigh', action='store_true')
fail_group.add_argument("--fail-on-medium", help="Exit with failed signal if medium severity vulnerabilities are found",
                        dest='failMedium', action='store_true')
fail_group.add_argument("--fail-on-low", help="Exit with failed signal if low severity vulnerabilities are found",
                        dest='failLow', action='store_true')

args = parser.parse_args()

# Main scope: config file
try:
    if not Path(args.config).is_file():
        print("Critical error:", "Could not locate config file: {}".format(args.config))
        sys.exit(15)  # EXIT_INVALID_CONFIG = 15

    config = parsers.load_from_json(args.config)
    # Image
    docker_image_grype = config["scanners"]["grype"]["image"]
    docker_image_trivy = config["scanners"]["trivy"]["image"]
    docker_image_syft = config["sbom"]["syft"]["image"]
    # Output format
    output_format_grype = config["scanners"]["grype"]["output_format"]
    output_format_trivy = config["scanners"]["trivy"]["output_format"]
    output_format_syft = config["sbom"]["syft"]["output_format"]
    # Cache dir, separated in config file for better (user) understanding
    cache_dir_grype = "{}:{}".format(config["scanners"]["grype"]["cache_dir"]["cache_dir_host"],
                                     config["scanners"]["grype"]["cache_dir"]["cache_dir_container"])
    cache_dir_trivy = "{}:{}".format(config["scanners"]["trivy"]["cache_dir"]["cache_dir_host"],
                                     config["scanners"]["trivy"]["cache_dir"]["cache_dir_container"])
    # Environment variables
    environment_vars_grype = config["scanners"]["grype"]["environment_vars"]
    # Results
    results_grype_filename = config["scanners"]["grype"]["output_filename"]
    results_trivy_filename = config["scanners"]["trivy"]["output_filename"]
    results_syft_filename = config["sbom"]["syft"]["output_filename"]
    # Input
    targets_file = config["input"]["targets"]
    # Output
    sinker_output_folder = config["output"]["sinker_output_folder"]
    results_destination = config["output"]["sinker_results_file"]
    bool_command_line_args = config["output"]["command_line_args"]
    bool_docker_version = config["output"]["docker_version"]
    # Logging
    verbose_mode = config["logging"]["verbose_stdout"]
    logging_enabled = config["logging"]["logging_enabled"]
    logging_as_json = config["logging"]["logging_as_json"]
    logging_overwrite_file_if_exists = config["logging"]["logging_overwrite_file_if_exists"]
    log_level = config["logging"]["logging_level"]
    log_output = config["logging"]["logging_file"]
    log_sep = config["logging"]["logging_separator"]
    log_datetime_format = config["logging"]["logging_datetime_format"]
    # Reporting
    report_by_artifact = config["reporting"]["by_artifact"]
    report_by_severity = config["reporting"]["by_severity"]
    report_by_scanner = config["reporting"]["by_scanner"]
    report_unanimous_findings = config["reporting"]["unanimous_findings"]
    report_disputed_findings = config["reporting"]["disputed_findings"]
    # Settings
    bool_ignore_running_as_root = config["settings"]["ignore_running_as_root"]
    bool_prune_containers_after_scan = config["settings"]["prune_containers_after_scan"]
    bool_prune_untagged_images_after_scan = config["settings"]["prune_untagged_images_after_scan"]
    bool_remove_scanner_images_after_scan = config["settings"]["remove_scanner_images_after_scan"]
    bool_remove_target_images_after_scan = config["settings"]["remove_target_images_after_scan"]
    # CI, fail on findings
    bool_fail_on_critical = config["ci"]["fail_on_findings"]["fail_on_critical"]
    bool_fail_on_high = config["ci"]["fail_on_findings"]["fail_on_high"]
    bool_fail_on_medium = config["ci"]["fail_on_findings"]["fail_on_medium"]
    bool_fail_on_low = config["ci"]["fail_on_findings"]["fail_on_low"]
    # CI, exit signals
    EXIT_OK = int(config["ci"]["exit_signals"]["exit_ok"])
    EXIT_FAIL_LOW = int(config["ci"]["exit_signals"]["exit_fail_low"])
    EXIT_FAIL_MEDIUM = int(config["ci"]["exit_signals"]["exit_fail_medium"])
    EXIT_FAIL_HIGH = int(config["ci"]["exit_signals"]["exit_fail_high"])
    EXIT_FAIL_CRITICAL = int(config["ci"]["exit_signals"]["exit_fail_critical"])

    # Overrides targets file from config file
    if args.targets:
        targets_file = args.targets

    # Overrides settings from config file
    if args.skipSyft:
        config["sbom"]["syft"]["enabled"] = False
    if args.skipSnyk:
        config["scanners"]["snyk"]["enabled"] = False
    if args.skipTrivy:
        config["scanners"]["trivy"]["enabled"] = False
    if args.skipGrype:
        config["scanners"]["grype"]["enabled"] = False

    # Overrides sinker_output_folder from config file
    if args.output:
        sinker_output_folder = args.output

    # Overrides ignore_running_as_root from config file
    if args.ignoreRoot:
        bool_ignore_running_as_root = True

    # Overrides verbose_mode from config file
    if args.verbose:
        verbose_mode = True

    # Checks if forceDockerPull has a valid value
    if args.forceDockerPull not in ["always", "missing", "never"]:
        args.forceDockerPull = "missing"

    # Main JSON for the app
    json_sinker = {}

    # To get scanner versions only once and store them
    version_syft, version_snyk, version_trivy = "", "", ""

except (PermissionError, FileNotFoundError, KeyError):
    # Calling helpers module here raised a circular import exception
    log_and_print("critical", "Could not locate or understand config file: {}".format(args.config))
    sys.exit(15)  # EXIT_INVALID_CONFIG = 15


if __name__ == "__main__":
    # clean_up() depends on config[] and config section above depends on ArgParser (defined before)

    # If --version flag, print version and exit
    args.version and helpers.print_version() and sys.exit(helpers.EXIT_OK)

    # If --only-updates, call update functions and exit
    if args.onlyUpdates:
        update_vulnerability_databases(config)
        sys.exit(EXIT_OK)

    # If --only-cleanup flag, perform clean up and exit
    args.onlyCleanup and clean_up() and sys.exit(EXIT_OK)

    # If --fresh-start flag, perform a full clean-up and exit
    args.freshStart and fresh_start() and sys.exit(EXIT_OK)

    # If --only-process-json flag, parse JSON file and exit
    if args.processJSON:
        process_json(parsers.load_from_json(args.processJSON))
        sys.exit(EXIT_OK)

    # All other options: follow normal execution.
    main()
