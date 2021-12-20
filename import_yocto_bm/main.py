import os
import sys
import time

from import_yocto_bm import global_values
from import_yocto_bm import config
from import_yocto_bm import process
from import_yocto_bm import utils


if config.args.bblayers_out != '':
    config.args.no_cve_check = True


def main():
    print("Yocto build manifest import into Black Duck Utility v2.0")
    print("---------------------------------------------------------\n")

    bd = None

    wizlist = config.check_args()

    if not global_values.offline and global_values.url != '':
        bd = config.connect()
        if bd is None:
            wizlist.append('BD_SERVER')
            wizlist.append('BD_API_TOKEN')
            wizlist.append('BD_TRUST_CERT')

    if config.args.manifest == "":
        if not config.check_yocto_build_folder():
            wizlist.append('MANIFEST_FILE')
            wizlist.append('DEPLOY_DIR')
        elif os.path.isabs(config.args.yocto_build_folder):
            print("INFO: Will use Yocto build folder '{}'\n".format(config.args.yocto_build_folder))
        else:
            print("INFO: Will use Yocto build folder '{}' (Absolute path '{}')\n".format(
                config.args.yocto_build_folder, os.path.abspath(config.args.yocto_build_folder)))

    if config.args.replacefile != "":
        if not process.proc_replacefile():
            print('WARNING: Replacefile {} is not valid - will be ignored'.format(config.args.replacefile))
            config.args.replacefile = ''

    wizlist = wizlist + config.find_files()

    if not config.args.nowizard and (config.args.wizard or len(wizlist) > 0) and not config.args.cve_check_only:
        config.do_wizard(wizlist)
        if bd is None and global_values.url != '' and not global_values.offline:
            bd = config.connect()
            if bd is None:
                print(f'ERROR: Unable to connect to BD server {global_values.url}')
                sys.exit(2)

    if not config.args.cve_check_only:
        process.proc_yocto_project(config.args.manifest)

        if not global_values.offline:
            print("\nUploading scan to Black Duck server ...")
            if utils.upload_json(bd, config.args.output_json):
                print("Scan file uploaded successfully\nBlack Duck project '{}/{}' created.".format(
                    config.args.project, config.args.version))
            else:
                print("ERROR: Unable to upload scan file")
                sys.exit(3)

    if not global_values.offline and config.args.cve_check_file != "" and not config.args.no_cve_check:

        print("\nProcessing CVEs ...")

        if not config.args.cve_check_only:
            print("Waiting for Black Duck server scan completion before continuing ...")
            # Need to wait for scan to process into queue - sleep 15
            time.sleep(0)

        try:
            print("- Reading Black Duck project ...")
            proj, ver = utils.get_projver(bd, config.args)
            while ver is None:
                time.sleep(10)
                proj, ver = utils.get_projver(bd, config.args)

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
            cvefile = open(config.args.cve_check_file, "r")
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
