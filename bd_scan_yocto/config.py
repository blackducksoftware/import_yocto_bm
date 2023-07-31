import os
import argparse
import shutil
import sys
import glob
import subprocess
import re

from blackduck import Client
from bd_scan_yocto import global_values

parser = argparse.ArgumentParser(description='Import Yocto build manifest to BD project version',
                                 prog='bd_scan_yocto')

# parser.add_argument("projfolder", nargs="?", help="Yocto project folder to analyse", default=".")

parser.add_argument("--blackduck_url", type=str, help="Black Duck server URL", default="")
parser.add_argument("--blackduck_api_token", type=str, help="Black Duck API token ", default="")
parser.add_argument("--blackduck_trust_cert", help="Black Duck trust server cert", action='store_true')
parser.add_argument("--detect-jar-path", help="Synopsys Detect jar path", default="")
parser.add_argument("-p", "--project", help="Black Duck project to create (REQUIRED)", default="")
parser.add_argument("-v", "--version", help="Black Duck project version to create (REQUIRED)", default="")
# parser.add_argument("-y", "--yocto_build_folder",
#                     help="Yocto build folder (required if CVE check required or manifest file not specified)",
#                     default=".")
parser.add_argument("--oe_build_env",
                    help="Yocto build environment config file (default 'oe-init-build-env')",
                    default="oe-init-build-env")
parser.add_argument("-t", "--target", help="Yocto target (default core-image-sato)", default="core-image-sato")
parser.add_argument("-m", "--manifest",
                    help="Built license.manifest file)",
                    default="")
parser.add_argument("--machine", help="Machine Architecture (for example 'qemux86-64')",
                    default="")
parser.add_argument("--no_detect_for_bitbake", help="Skip running Detect for Bitbake dependencies", action='store_true')
parser.add_argument("--cve_check_only", help="Only check for patched CVEs from cve_check and update existing project",
                    action='store_true')
parser.add_argument("--no_cve_check", help="Skip check for and update of patched CVEs", action='store_true')
parser.add_argument("--cve_check_file",
                    help="CVE check output file (if not specified will be determined from conf files)", default="")
parser.add_argument("--report",
                    help="Output report.txt file of matched recipes",
                    default="")
# parser.add_argument("--bblayers_out",
#                     help='''Specify file containing 'bitbake-layers show-recipes' output (do not run command) & bypass
#                     checks for revisions in recipe_info files''',
#                     default="")
parser.add_argument("--wizard", help="Start command line wizard (Wizard will run by default if config incomplete)",
                    action='store_true')
parser.add_argument("--nowizard", help="Do not use wizard (command line batch only)", action='store_true')
parser.add_argument("--scan_snippet_layers",
                    help='''If --scan_unmatched_recipes is set, specify a command-delimited list of layers where recipes will also be
                    Snippet scanned''',
                    default="")
# parser.add_argument("--deploy_dir",
#                     help="Top Level directory where artefacts are written (usually poky/build/tmp/deploy)",
#                     default="")
parser.add_argument("--download_dir",
                    help="Download directory where original packages are downloaded (usually poky/build/downloads)",
                    default="")
parser.add_argument("--rpm_dir",
                    help="Download directory where rpm packages are downloaded (usually poky/build/tmp/deploy/rpm/<ARCH>)",
                    default="")
parser.add_argument("--debug", help="DEBUG mode - skip various checks", action='store_true')

args = parser.parse_args()


def check_args():
    # if platform.system() != "Linux":
    #     print('''Please use this program on a Linux platform or extract data from a Yocto build then
    #     use the --bblayers_out option to scan on other platforms\nExiting''')
    #     sys.exit(2)

    if args.oe_build_env != '':
        global_values.oe_build_env = args.oe_build_env

    if args.debug:
        global_values.debug = True
    else:
        if not os.path.isfile(global_values.oe_build_env):
            print(f"ERROR: Cannot find Yocto build environment config file '{global_values.oe_build_env}'")
            sys.exit(2)

        # if os.system(f"source {global_values.oe_build_env}; bitbake --help >/dev/null")
        # # if shutil.which("bitbake") is None:
        #     print("ERROR: Yocto environment not set (run 'source oe-init-build-env')")
        #     sys.exit(2)

        if shutil.which("java") is None:
            print("ERROR: Java runtime is required and should be on the PATH")
            sys.exit(2)

    url = os.environ.get('BLACKDUCK_URL')
    if args.blackduck_url != '':
        global_values.bd_url = args.blackduck_url
    elif url != '':
        global_values.bd_url = url
    else:
        print("WARNING: Black Duck URL not specified")

    if args.project != "" and args.version != "":
        global_values.bd_project = args.project
        global_values.bd_version = args.version
    else:
        print("WARNING: Black Duck project/version not specified")

    api = os.environ.get('BLACKDUCK_API_TOKEN')
    if args.blackduck_api_token != '':
        global_values.bd_api = args.blackduck_api_token
    elif api != '':
        global_values.bd_api = api
    else:
        print("WARNING: Black Duck API Token not specified")

    trustcert = os.environ.get('BLACKDUCK_TRUST_CERT')
    if trustcert == 'true' or args.blackduck_trust_cert:
        global_values.bd_trustcert = True

    # if args.yocto_build_folder != '':
    #     if not os.path.isdir(args.yocto_build_folder):
    #         print(f"WARNING: Specified Yocto build folder '{args.yocto_build_folder}' does not exist")
    #     else:
    #         global_values.yocto_build_folder = os.path.abspath(args.yocto_build_folder)

    # if args.deploy_dir != '':
    #     if not os.path.isdir(args.deploy_dir):
    #         print(f"WARNING: Specified deploy folder '{args.deploy_dir}' does not exist")
    #     else:
    #         global_values.deploy_dir = os.path.abspath(args.deploy_dir)

    if args.download_dir != '':
        if not os.path.isdir(args.download_dir):
            print(f"WARNING: Specified download package folder '{args.download_dir}' does not exist")
        else:
            global_values.download_dir = os.path.abspath(args.download_dir)

    if args.rpm_dir != '':
        if not os.path.isdir(args.rpm_dir):
            print(f"WARNING: Specified download rpm folder '{args.rpm_dir}' does not exist")
        else:
            global_values.rpm_dir = os.path.abspath(args.rpm_dir)

    if args.cve_check_only or args.cve_check_file != '':
        global_values.cve_check = True

    if args.cve_check_file != "":
        if args.no_cve_check:
            print("ERROR: Options cve_check_file and no_cve_check cannot be specified together")
            sys.exit(2)

        if not os.path.isfile(args.cve_check_file):
            print(f"WARNING: CVE check output file '{args.cve_check_file}' does not exist")
        else:
            global_values.cve_check_file = args.cve_check_file

    if args.cve_check_only and args.no_cve_check:
        print("ERROR: Options --cve_check_only and --no_cve_check cannot be specified together")
        sys.exit(2)

    if args.manifest != "":
        if not os.path.isfile(args.manifest):
            print(f"WARNING: Manifest file '{args.manifest}' does not exist")
        else:
            global_values.manifest_file = args.manifest

    if args.machine != "":
        global_values.machine = args.machine

    if args.detect_jar_path != "" and not os.path.isfile(args.detect_jar_path):
        print(f"ERROR: Detect jar file {args.detect_jar_path} does not exist")
        sys.exit(2)
    else:
        global_values.detect_jar = args.detect_jar_path

    if args.no_detect_for_bitbake == 'true':
        global_values.run_detect_for_bitbake = False

    return


def connect():
    if global_values.bd_url == '':
        return None

    bd = Client(
        token=global_values.bd_api,
        base_url=global_values.bd_url,
        timeout=30,
        verify=global_values.bd_trustcert  # TLS certificate verification
    )
    try:
        bd.list_resources()
    except Exception as exc:
        print('WARNING: Unable to connect to Black Duck server - {}'.format(str(exc)))
        return None

    print('INFO: Connected to Black Duck server {}'.format(global_values.bd_url))
    return bd


def find_files_folders():
    # New Logic 2023_07
    # Need to find:
    # - MANIFEST_FILE
    # - DEPLOY_DIR
    # - TMPDIR
    # - MACHINE
    # - rootfs.cve

    # tmpdir = ""
    if not global_values.debug:
        print("- Running 'bitbake -e' ...")
        output = subprocess.check_output(['bitbake', '-e'], stderr=subprocess.STDOUT)
        mystr = output.decode("utf-8").strip()
        lines = mystr.splitlines()

        for mline in lines:
            if re.search("^(MANIFEST_FILE|DEPLOY_DIR|MACHINE_ARCH|DL_DIR|DEPLOY_DIR_RPM)=", mline):

                # if re.search('^TMPDIR=', mline):
                #     tmpdir = mline.split('=')[1]
                val = mline.split('=')[1].strip('\"')
                if global_values.manifest_file == '' and re.search('^MANIFEST_FILE=', mline):
                    global_values.manifest = val
                    print("Bitbake Env: manifestfile={}".format(global_values.manifest_file))
                # elif global_values.deploy_dir == '' and re.search('^DEPLOY_DIR=', mline):
                #     global_values.deploy_dir = val
                #     print("Bitbake Env: deploydir={}".format(global_values.deploy_dir))
                elif global_values.machine == '' and re.search('^MACHINE_ARCH=', mline):
                    global_values.machine = val
                    print("Bitbake Env: machine={}".format(global_values.machine))
                elif global_values.download_dir == '' and re.search('^DL_DIR=', mline):
                    global_values.download_dir = val
                    print("Bitbake Env: download_dir={}".format(global_values.download_dir))
                elif global_values.rpm_dir == '' and re.search('^DEPLOY_DIR_RPM=', mline):
                    global_values.rpm_dir = val
                    print("Bitbake Env: pm_dir={}".format(global_values.rpm_dir))

    if global_values.cve_check_file == "" and global_values.cve_check:
        if global_values.target == '':
            print("WARNING: CVE check file not specified and it could not be determined as Target not specified")
        else:
            imgdir = os.path.join(global_values.deploy_dir, "images", global_values.machine)
            cvefile = ""
            for file in sorted(os.listdir(imgdir)):
                if file.startswith(global_values.target + "-" + global_values.machine + "-") and \
                        file.endswith('rootfs.cve'):
                    cvefile = os.path.join(imgdir, file)

            if not os.path.isfile(cvefile):
                print("WARNING: CVE check file could not be located")
            else:
                print("INFO: Located CVE check output file {}".format(cvefile))
                global_values.cve_check_file = cvefile

    return


def input_number(prompt):
    print(f'{prompt} (q to quit): ', end='')
    val = input()
    while not val.isnumeric() and val.lower() != 'q':
        print('WARNING: Please enter a number (or q)')
        print(f'{prompt}: ', end='')
        val = input()
    if val.lower() != 'q':
        return int(val)
    else:
        print('Terminating')
        sys.exit(2)


def input_file(prompt, accept_null, file_exists):
    if accept_null:
        prompt_help = '(q to quit, Enter to skip)'
    else:
        prompt_help = '(q to quit)'
    print(f'{prompt} {prompt_help}: ', end='')
    val = input()
    while (file_exists and not os.path.isfile(val)) and val.lower() != 'q':
        if accept_null and val == '':
            break
        print(f'WARNING: Invalid input ("{val}" is not a file)')
        print(f'{prompt} {prompt_help}: ', end='')
        val = input()
    if val.lower() != 'q' or (accept_null and val == ''):
        return val
    else:
        print('Terminating')
        sys.exit(2)


def input_folder(prompt):
    prompt_help = '(q to quit)'
    print(f'{prompt} {prompt_help}: ', end='')
    val = input()
    while not os.path.isdir(val) and val.lower() != 'q':
        if val == '':
            break
        print(f'WARNING: Invalid input ("{val}" is not a folder)')
        print(f'{prompt} {prompt_help}: ', end='')
        val = input()
    if val.lower() != 'q':
        return val
    else:
        print('Terminating')
        sys.exit(2)


def input_string(prompt):
    print(f'{prompt} (q to quit): ', end='')
    val = input()
    while len(val) == 0 and val != 'q':
        print(f'{prompt}: ', end='')
        val = input()
    if val.lower() != 'q':
        return val
    else:
        print('Terminating')
        sys.exit(2)


def input_string_default(prompt, default):
    print(f"{prompt} [Press return for '{default}'] (q to quit): ", end='')
    val = input()
    if val.lower() == 'q':
        sys.exit(2)
    if len(val) == 0:
        print('Terminating')
        return default
    else:
        return val


def input_yesno(prompt):
    accept_other = ['n', 'q', 'no', 'quit']
    accept_yes = ['y', 'yes']

    print(f'{prompt} (y/n/q): ', end='')
    val = input()
    while val.lower() not in accept_yes and val.lower() not in accept_other:
        print('WARNING: Please enter y or n')
        print(f'{prompt}: ', end='')
        val = input()
    if val.lower() == 'q':
        sys.exit(2)
    if val.lower() in accept_yes:
        return True
    return False


def input_filepattern(pattern, filedesc):
    retval = ''
    enterfile = False
    if input_yesno(f"Do you want to search recursively for '{filedesc}'?"):
        files_list = glob.glob(pattern, recursive=True)
        if len(files_list) > 0:
            print(f'Please select the {filedesc} file to be used: ')
            files_list = ['None of the below'] + files_list
            for i, f in enumerate(files_list):
                print(f'\t{i}: {f}')
            val = input_number('Please enter file entry number')
            if val == 0:
                enterfile = True
            else:
                retval = files_list[val]
        else:
            print(f'WARNING: Unable to find {filedesc} files ...')
            enterfile = True
    else:
        enterfile = True

    if enterfile:
        retval = input_file(f'Please enter the {filedesc} file path', False, True)

    if not os.path.isfile(retval):
        print(f'ERROR: Unable to locate {filedesc} file - exiting')
        sys.exit(2)
    return retval


def do_wizard():
    print('\nRUNNING WIZARD ...\n')
    # wiz_categories = [
    #     'BD_SERVER',
    #     'BD_API_TOKEN',
    #     'BD_TRUST_CERT',
    #     'PROJECT',
    #     'VERSION',
    #     'DEPLOY_DIR',
    #     'DOWNLOAD_DIR',
    #     'RPM_DIR',
    #     'CVE_CHECK',
    # ]
    wiz_dict = [
        {'value': 'global_values.bd_url', 'prompt': 'Black Duck server URL', 'vtype': 'string_default'},
        {'value': 'global_values.bd_api', 'prompt': 'Black Duck API token', 'vtype': 'string_default'},
        {'value': 'global_values.bd_trustcert', 'prompt': 'Trust BD Server certificate', 'vtype': 'yesno'},
        {'value': 'global_values.bd_project', 'prompt': 'Black Duck project name', 'vtype': 'string'},
        {'value': 'global_values.bd_version', 'prompt': 'Black Duck version name', 'vtype': 'string'},
        {'value': 'global_values.manifest_file', 'prompt': 'Manifest file path', 'vtype': 'file_pattern',
         'pattern': '**/license.manifest', 'filename': 'license.manifest file'},
        {'value': 'global_values.deploy_dir', 'prompt': 'Yocto deploy folder', 'vtype': 'folder'},
        {'value': 'global_values.download_dir', 'prompt': 'Yocto package download folder', 'vtype': 'folder'},
        {'value': 'global_values.rpm_dir', 'prompt': 'Yocto rpm package download folder', 'vtype': 'folder'},
        {'value': 'global_values.cve_check',
         'prompt': 'Do you want to run a CVE check to patch CVEs in the BD project which have been patched locally?',
         'vtype': 'yesno'},
        {'value': 'global_values.cve_check_file', 'prompt': 'CVE check file path',
         'vtype': 'file_pattern', 'pattern': '**/rootfs.cve', 'filename': 'CVE check output file'},
    ]

    cvecheck = False
    for wiz_entry in wiz_dict:
        val = ''
        if eval(wiz_entry['value']) == '':
            if wiz_entry['vtype'] == 'string':
                val = input_string(wiz_entry['prompt'])
            elif wiz_entry['vtype'] == 'string_default':
                val = input_string_default(wiz_entry['prompt'], wiz_entry['default'])
                # val = input_string(wiz_help[wiz_categories.index(cat)]['prompt'])
            elif wiz_entry['vtype'] == 'yesno':
                val = input_yesno(wiz_entry['prompt'])
            elif wiz_entry['vtype'] == 'file':
                val = input_file(wiz_entry['prompt'], False, True)
            elif wiz_entry['vtype'] == 'folder':
                val = input_folder(wiz_entry['prompt'])
            elif wiz_entry['vtype'] == 'file_pattern':
                val = input_filepattern("**/license.manifest", "'license.manifest'")

            globals()[wiz_entry['value']] = val

    if cvecheck:
        args.cve_check_file = input_filepattern("**/*.cve", "CVE check output file")

    repfile = input_file('Report file name', True, False)
    if repfile != '':
        args.report = repfile

    return
