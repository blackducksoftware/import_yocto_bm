import os
import sys
import time

from bd_scan_yocto import global_values
from bd_scan_yocto import config
from bd_scan_yocto import process
from bd_scan_yocto import utils


# if config.args.bblayers_out != '':
#     config.args.no_cve_check = True


def main():
    print(f"Yocto Black Duck Signature Scan Utility v{global_values.version}")
    print("---------------------------------------------------------\n")

    bd = None

    config.check_args()

    config.find_files_folders()

    if not config.args.nowizard:
        config.do_wizard()

    bd = config.connect()
    if bd is None:
        print(f"ERROR: Cannot connect to specified BD server {global_values.bd_url}")
        sys.exit(3)

    if global_values.run_detect_for_bitbake:
        process.run_detect_for_bitbake()

    if not config.args.cve_check_only:
        process.proc_yocto_project(global_values.manifest_file)

    if global_values.cve_check_file != "" and not config.args.no_cve_check:

        print("\nProcessing CVEs ...")

        if not config.args.cve_check_only:
            print("Waiting for Black Duck server scan completion before continuing ...")
            # Need to wait for scan to process into queue - sleep 15
            time.sleep(0)

        try:
            print("- Reading Black Duck project ...")
            proj, ver = utils.get_projver(bd, config.args)
            count = 1
            while ver is None:
                time.sleep(10)
                proj, ver = utils.get_projver(bd, config.args)
                count += 1
                if count > 20:
                    print(f"Unable to locate project {proj} and version '{ver}' - terminating")
                    sys.exit(1)

        except Exception as e:
            print("ERROR: Unable to get project version from API\n" + str(e))
            sys.exit(3)

        # if not wait_for_scans(bd, ver):
        #     print("ERROR: Unable to determine scan status")
        #     sys.exit(3)

        if not utils.wait_for_bom_completion(bd, ver):
            print("ERROR: Unable to determine BOM status")
            sys.exit(3)

        print("- Loading CVEs from cve_check log ...")

        try:
            cvefile = open(global_values.cve_check_file, "r")
            cvelines = cvefile.readlines()
            cvefile.close()
        except Exception as e:
            print("ERROR: Unable to open CVE check output file\n" + str(e))
            sys.exit(3)

        patched_vulns = []
        pkgvuln = {}
        cves_in_bm = 0
        for line in cvelines:
            arr = line.split(":")
            if len(arr) > 1:
                key = arr[0]
                value = arr[1].strip()
                if key == "PACKAGE NAME":
                    pkgvuln['package'] = value
                elif key == "PACKAGE VERSION":
                    pkgvuln['version'] = value
                elif key == "CVE":
                    pkgvuln['CVE'] = value
                elif key == "CVE STATUS":
                    pkgvuln['status'] = value
                    if pkgvuln['status'] == "Patched":
                        patched_vulns.append(pkgvuln['CVE'])
                        if pkgvuln['package'] in global_values.packages_list:
                            cves_in_bm += 1
                    pkgvuln = {}

        print("      {} total patched CVEs identified".format(len(patched_vulns)))
        if not config.args.cve_check_only:
            print(
                '''      {} Patched CVEs within packages in build manifest (including potentially mismatched 
            CVEs which should be ignored)'''.format(
                    cves_in_bm))
        if len(patched_vulns) > 0:
            process.process_patched_cves(bd, ver, patched_vulns)
    print("Done")


if __name__ == "__main__":
    main()
