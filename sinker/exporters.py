import core
import helpers
import parsers

from pathlib import Path
from prettytable import PrettyTable


def table_sorter(csv_table):
    import csv
    from operator import itemgetter
    import io

    reader = csv.reader(str(csv_table).split(), delimiter=',', dialect='unix', quotechar='"')
    data = [tuple(row) for row in reader]

    def multisort(xs, specs):
        for key, reverse in reversed(specs):
            xs.sort(key=itemgetter(key), reverse=reverse)
        return xs

    # 5 = 'Severity_Order', 0 = 'Target Image', 1 = 'Artifact', 2 = 'Upstream'
    multisorted_csv_table = multisort(
        list(data), ((5, True), (0, False), (1, False), (2, False))
    )

    data = [list(row) for row in multisorted_csv_table]

    output = io.StringIO()
    csv.register_dialect('unix2', delimiter=',', quoting=csv.QUOTE_MINIMAL)
    writer = csv.writer(output, dialect='unix2')
    writer.writerows(data)
    # print(output)
    # print(output.getvalue())

    return output.getvalue()


def create_prettytable(config_output_object, json_sinker):
    """
    Creates an empty PrettyTable, populates it with the content of json_sinker and prints it
    :param config_output_object: Output subsection from Config JSON
    :param json_sinker: JSON object containing the vulnerabilities
    :return: True
    """
    if not config_output_object["export_to_table"]["enabled"]:
        core.log_and_print("debug", "Exporting to table is disabled.")
        return

    table = PrettyTable()

    int_severity_order = parsers.load_from_json("severity.conf.json")

    # Table header
    table.field_names = \
        ["TargetImage", "Artifact", "Upstream", "ID", "Severity", "Severity_Order", "Version", "FixedVersion"]
    # Table rows
    for target_image in json_sinker["reporting"]:
        for vuln in json_sinker["reporting"][target_image]["by_id"]:
            artifact = vuln["artifact"]
            upstream = vuln["upstream"]
            vuln_id = vuln["id"]
            severity = vuln["severity"]
            severity_order = int_severity_order.get(vuln["severity"])
            installed_version = vuln["installed_version"]
            try:
                if type(vuln["fixed_version"]) == list:
                    fixed_version = vuln["fixed_version"][0]
                else:
                    fixed_version = vuln["fixed_version"]
            except IndexError:
                fixed_version = ""
            # finding_type = vuln["finding_type"]

            table.add_row(
                [target_image, artifact, upstream, vuln_id, severity, severity_order, installed_version, fixed_version]
            )

    return sort_prettytable(table)


def sort_prettytable(prettytable_object):
    """
    Exports PrettyTable object to stdout and/or file
    # :param config_output_object: Output subsection from Config JSON
    :param prettytable_object: PrettyTable object to be exported
    :return: True
    """
    # PrettyTable sorting mechanism are very basic. Let's use a function for this.
    # First, export to CSV to get it sorted out
    sorted_csv_table = prettytable_object.get_csv_string()
    # Second, get sorted CSV table
    multisorted_csv_table = table_sorter(sorted_csv_table)

    # Third, import the CSV table as an object again
    table = PrettyTable()
    table.field_names = \
        ["Target Image", "Artifact", "Upstream", "ID", "Severity", "Severity_Order", "Version", "Fixed Version"]
    for line in multisorted_csv_table.splitlines():
        if line.strip().split(",")[0] == prettytable_object.field_names[0]:
            continue
        table.add_row(line.strip().split(","))

    # Fourth, the extra column is removed, no matter what sorting method was chosen
    table.del_column("Severity_Order")
    # Fifth, finally export the table to string
    printable_table = table.get_string()

    return printable_table


def export_prettytable(config_output_object, prettytable_string):
    if config_output_object["export_to_table"]["export_to_stdout"]:
        print(prettytable_string)

    if config_output_object["export_to_table"]["export_to_file"]:
        full_destination = "{}{}".format(
            config_output_object["sinker_output_folder"],
            config_output_object["export_to_table"]["export_to_file"]).replace('//', '/')
        write_to_text(full_destination, prettytable_string)


def write_to_text(destination_file, prettytable_string):
    """
    Writes PrettyTable object to text file.
    :param destination_file: Destination file where data will be written
    :param prettytable_string: PrettyTable object to be exported
    :return: True for success, otherwise exits with error code in case of exception
    """
    try:
        # Creates recursive path if it doesn't exist (should have been created by start_logging()
        Path(core.sinker_output_folder).mkdir(parents=True, exist_ok=True)
        with open(destination_file, 'w') as f:
            f.write(prettytable_string)

    except PermissionError:
        helpers.dest_not_writable(destination_file)

    else:
        core.log_and_print("debug", "Exported vulnerabilities table to {}.".format(destination_file))
