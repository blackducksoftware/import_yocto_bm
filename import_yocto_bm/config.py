import os
import argparse
import shutil
import sys
import glob

from blackduck import Client
from import_yocto_bm import global_values

parser = argparse.ArgumentParser(description='Import Yocto build manifest to BD project version',
                                 prog='import_yocto_bm')

# parser.add_argument("projfolder", nargs="?", help="Yocto project folder to analyse", default=".")

parser.add_argument("--blackduck_url", type=str, help="Black Duck server URL", default="")
parser.add_argument("--blackduck_api_token", type=str, help="Black Duck API token ", default="")
parser.add_argument("--blackduck_trust_cert", help="Black Duck trust server cert", action='store_true')
parser.add_argument("-p", "--project", help="Black Duck project to create (REQUIRED)", default="")
parser.add_argument("-v", "--version", help="Black Duck project version to create (REQUIRED)", default="")
parser.add_argument("-y", "--yocto_build_folder",
                    help="Yocto build folder (required if CVE check required or manifest file not specified)",
                    default=".")
parser.add_argument("-o", "--output_json",
                    help='''Output JSON bom file for manual import to Black Duck (instead of uploading the scan 
                    automatically)''',
                    default="")
parser.add_argument("--code_location_prefix", help="Add prefix to resulting code location name", default="")
parser.add_argument("-t", "--target", help="Yocto target (default core-poky-sato)", default="core-image-sato")
parser.add_argument("-m", "--manifest",
                    help="Input build license.manifest file (if not specified will be determined from conf files)",
                    default="")
parser.add_argument("-b", "--buildconf",
                    help="Build config file (if not specified poky/meta/conf/bitbake.conf will be used)", default="")
parser.add_argument("-l", "--localconf",
                    help="Local config file (if not specified poky/build/conf/local.conf will be used)", default="")
parser.add_argument("-r", "--replacefile", help="File containing layer/recipe replacement strings", default="")
parser.add_argument("--arch", help="Architecture (if not specified then will be determined from conf files)",
                    default="")
parser.add_argument("--cve_check_only", help="Only check for patched CVEs from cve_check and update existing project",
                    action='store_true')
parser.add_argument("--no_cve_check", help="Skip check for and update of patched CVEs", action='store_true')
parser.add_argument("--cve_check_file",
                    help="CVE check output file (if not specified will be determined from conf files)", default="")
parser.add_argument("--no_kb_check", help="Do not check recipes against KB", action='store_true')
parser.add_argument("--kb_recipe_dir", help="KB recipe file local copy", default="")
parser.add_argument("--report",
                    help="Output report.txt file of matched recipes",
                    default="")
parser.add_argument("--bblayers_out",
                    help='''Specify file containing 'bitbake-layers show-recipes' output (do not run command) & bypass
                    checks for revisions in recipe_info files''',
                    default="")
parser.add_argument("--wizard", help="Start command line wizard (Wizard will run by default if config incomplete)",
                    action='store_true')
parser.add_argument("--nowizard", help="Do not use wizard (command line batch only)", action='store_true')

args = parser.parse_args()


def check_args():
    wizlist = []
    if args.project != "" and args.version != "":
        pass
    else:
        print("WARNING: Black Duck project/version not specified")
        wizlist.append('PROJECT')
        wizlist.append('VERSION')

    # Check oe-pkgdata-util and bitbake commands are on PATH
    if args.bblayers_out == '':
        # if platform.system() != "Linux":
        #     print('''Please use this program on a Linux platform or extract data from a Yocto build then
        #     use the --bblayers_out option to scan on other platforms\nExiting''')
        #     sys.exit(2)

        if shutil.which("bitbake") is None or shutil.which("bitbake-layers") is None:
            print("WARNING: Yocto environment has probably not been set (no 'bitbake-layers' command)")
            wizlist.append('BBLAYERS_FILE')

    if args.output_json == '':
        if args.blackduck_url == '':
            global_values.url = os.environ.get('BLACKDUCK_URL')
        else:
            global_values.url = args.blackduck_url

        if args.blackduck_api_token == '':
            global_values.api = os.environ.get('BLACKDUCK_API_TOKEN')
        else:
            global_values.api = args.blackduck_api_token

        trustcert = os.environ.get('BLACKDUCK_TRUST_CERT')
        if trustcert == 'true' or args.blackduck_trust_cert:
            global_values.verify = True
            
        if global_values.url == '' or global_values.api == '':
            wizlist.append('BD_SERVER')
            wizlist.append('BD_API_TOKEN')
            wizlist.append('BD_TRUST_CERT')
            # globals.offline = True
    else:
        global_values.offline = True

    if not os.path.isdir(args.yocto_build_folder):
        print("WARNING: Specified Yocto build folder '{}' does not exist".format(args.yocto_build_folder))
        wizlist.append('MANIFEST_FILE')
        wizlist.append('DEPLOY_DIR')
    else:
        args.yocto_build_folder = os.path.abspath(args.yocto_build_folder)

    if args.cve_check_file != "" and args.no_cve_check:
        print("WARNING: Options cve_check_file and no_cve_check cannot be specified together".format(
            args.cve_check_file))
        wizlist.append('CVE_CHECK')

    if args.cve_check_file != "" and not os.path.isfile(args.cve_check_file):
        print("WARNING: CVE check output file '{}' does not exist".format(args.cve_check_file))
        wizlist.append('CVE_CHECK')

    if args.cve_check_only and args.no_cve_check:
        print("WARNING: Options --cve_check_only and --no_cve_check cannot be specified together")
        wizlist.append('CVE_CHECK')

    if args.output_json != "":
        print("WARNING: CVE checking not supported with --output_json option - will be skipped")
        args.no_cve_check = True
        global_values.do_upload = False

    if args.manifest != "" and not os.path.isfile(args.manifest):
        print("WARNING: Manifest file '{}' does not exist".format(args.manifest))
        wizlist.append('MANIFEST_FILE')
        wizlist.append('DEPLOY_DIR')

    if args.replacefile != "" and not os.path.isfile(args.replacefile):
        print("WARNING: Replacefile file '{}' does not exist".format(args.replacefile))
        wizlist.append('REPLACE_FILE')

    if args.kb_recipe_dir != '':
        if not os.path.isdir(args.kb_recipe_dir):
            print("ERROR: Black Duck KB data dir '{}' does not exist".format(args.kb_recipe_dir))
            sys.exit(2)
        else:
            krfile = os.path.join(args.kb_recipe_dir, 'kb_recipes.json')
            kefile = os.path.join(args.kb_recipe_dir, 'kb_entries.json')

        if not os.path.isfile(krfile) or not os.path.isfile(kefile):
            print("ERROR: Black Duck KB data files do not exist in folder '{}'".format(args.kb_recipe_dir))
            sys.exit(2)

    return wizlist


def connect():
    if global_values.url == '':
        return None

    bd = Client(
        token=global_values.api,
        base_url=global_values.url,
        timeout=30,
        verify=global_values.verify  # TLS certificate verification
    )
    try:
        bd.list_resources()
    except Exception as exc:
        print('WARNING: Unable to connect to Black Duck server - {}'.format(str(exc)))
        return None

    print('INFO: Connected to Black Duck server {}'.format(global_values.url))
    return bd


def check_yocto_build_folder():
    # check Yocto build dir:
    # yocto_build_folders = [ "build", "meta", "bitbake" ]
    yocto_build_folders = ["conf", "cache", "tmp"]
    yocto_files = []

    if os.path.isdir(os.path.join(args.yocto_build_folder, "build")):
        args.yocto_build_folder = os.path.join(args.yocto_build_folder, "build")

    for d in yocto_build_folders:
        if not os.path.isdir(os.path.join(args.yocto_build_folder, d)):
            print('WARNING: Project build folder {} does not appear to be a Yocto project folder which has been \
built ({} folder missing)'.format(args.yocto_build_folder, d))
            return False

    for f in yocto_files:
        if not os.path.isfile(os.path.join(args.yocto_build_folder, f)):
            print('WARNING: Project build folder {} does not appear to be a Yocto project folder \
({} file missing)'.format(args.yocto_build_folder, f))
            return False
    return True


def find_files():
    wizlist = []
    if args.bblayers_out != '':
        return wizlist

    # Locate yocto files & folders
    if args.buildconf == "":
        args.buildconf = os.path.join(args.yocto_build_folder, "..", "meta", "conf", "bitbake.conf")
    if not os.path.isfile(args.buildconf):
        print("WARNING: Cannot locate bitbake conf file {}".format(args.buildconf))
        wizlist.append('MANIFEST_FILE')
        wizlist.append('DEPLOY_DIR')
        return wizlist
    else:
        print(f"INFO: Found Yocto bitbake.conf file {args.buildconf}")
    if args.localconf == "":
        args.localconf = os.path.join(args.yocto_build_folder, "conf", "local.conf")
    if not os.path.isfile(args.localconf):
        print("WARNING: Cannot locate local bitbake conf file {}".format(args.localconf))
        wizlist.append('MANIFEST_FILE')
        wizlist.append('DEPLOY_DIR')
        return wizlist
    else:
        print(f"INFO: Found Yocto build local.conf file {args.localconf}")

    import re

    tmpdir = ""
    deploydir = ""
    machine = ""

    try:
        c = open(args.buildconf, "r")
        for cline in c:
            if re.search('^TMPDIR ', cline):
                tmpdir = cline.split()[2]
            if re.search('^DEPLOY_DIR ', cline):
                deploydir = cline.split()[2]
        c.close()
    except Exception as e:
        print("WARNING: Unable to read bitbake.conf file {}\n".format(args.buildconf) + str(e))
        wizlist.append('MANIFEST_FILE')
        wizlist.append('DEPLOY_DIR')
        return wizlist

    try:
        lfile = open(args.localconf, "r")
        for line in lfile:
            if re.search('^TMPDIR ', line):
                tmpdir = line.split()[2]
            if re.search('^DEPLOY_DIR ', line):
                deploydir = line.split()[2]
            if re.search('^MACHINE ', line):
                machine = line.split()[2]
        lfile.close()
    except Exception as e:
        print("WARNING: Unable to read local.conf file {}\n".format(args.localconf) + str(e))
        wizlist.append('MANIFEST_FILE')
        wizlist.append('DEPLOY_DIR')
        return wizlist
    print(f'INFO: Determined tmpdir {tmpdir}, deploydir {deploydir} and machine {machine} from config files')

    if tmpdir != "":
        tmpdir = tmpdir.replace('${TOPDIR}', args.yocto_build_folder)
        tmpdir = tmpdir.strip('"')
        tmpdir = os.path.expandvars(tmpdir)
    else:
        tmpdir = os.path.join(args.yocto_build_folder, "tmp")
    if not os.path.isdir(tmpdir):
        print("WARNING: TMPDIR does not exist {}\n".format(tmpdir))
        wizlist.append('MANIFEST_FILE')
        wizlist.append('DEPLOY_DIR')
        return wizlist

    if deploydir != "":
        deploydir = deploydir.replace('${TMPDIR}', tmpdir)
        deploydir = deploydir.strip('"')
        global_values.deploydir = os.path.expandvars(deploydir)
    else:
        global_values.deploydir = os.path.join(args.yocto_build_folder, "tmp", "deploy")
    if not os.path.isdir(deploydir):
        print("WARNING: DEPLOYDIR does not exist {}\n".format(deploydir))
        wizlist.append('MANIFEST_FILE')
        wizlist.append('DEPLOY_DIR')
        return wizlist

    if args.arch == "":
        args.arch = machine.strip('"')

    licdir = os.path.join(global_values.deploydir, "licenses")
    if args.manifest == "":
        manifestdir = ""
        if not os.path.isdir(licdir):
            print("WARNING: License directory {} does not exist - check Yocto project has been built".format(licdir))
            wizlist.append('MANIFEST_FILE')
            wizlist.append('DEPLOY_DIR')
            return wizlist

        for file in sorted(os.listdir(licdir)):
            if file.startswith(args.target + "-" + args.arch + "-"):
                manifestdir = os.path.join(licdir, file)

        manifestfile = os.path.join(manifestdir, "license.manifest")
        if not os.path.isfile(manifestfile):
            print('WARNING: Build manifest file {} does not exist - check Yocto project has been built'.format(
                    manifestfile))
            wizlist.append('MANIFEST_FILE')
            wizlist.append('DEPLOY_DIR')
            return wizlist
        else:
            print("INFO: Located manifest file {}".format(manifestfile))

        args.manifest = manifestfile

    if args.cve_check_file == "" and not args.no_cve_check:
        imgdir = os.path.join(deploydir, "images", args.arch)
        cvefile = ""
        for file in sorted(os.listdir(imgdir)):
            if file.startswith(args.target + "-" + args.arch + "-") and file.endswith("rootfs.cve"):
                cvefile = os.path.join(imgdir, file)

        if not os.path.isfile(cvefile):
            print("WARNING: CVE check file could not be located")
            wizlist.append('CVE_CHECK')
            return wizlist

        else:
            print("INFO: Located CVE check output file {}".format(cvefile))
            args.cve_check_file = cvefile

    return wizlist


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
        return default
    else:
        print('Terminating')
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
    files_list = glob.glob(pattern, recursive=True)
    if len(files_list) > 0:
        print(f'Please select the {filedesc} file to be used: ')
        files_list = ['None of the below'] + files_list
        for i, f in enumerate(files_list):
            print(f'\t{i}: {f}')
        val = input_number('Please enter file entry number')
        if val == 0:
            retval = input_file(f'Please enter the {filedesc} file path', False, True)
        else:
            retval = files_list[val]
    else:
        print(f'WARNING: Unable to find {filedesc} files ...')
        retval = input_file(f'Please enter the {filedesc} file path', False, True)
    if not os.path.isfile(retval):
        print(f'ERROR: Unable to locate {filedesc} file - exiting')
        sys.exit(2)
    return retval


def do_wizard(wlist):
    print('\nRUNNING WIZARD ...\n')
    wiz_categories = [
        'PROJECT',
        'VERSION',
        'BD_SERVER',
        'BD_API_TOKEN',
        'BD_TRUST_CERT',
        'REPLACE_FILE',
        'CVE_CHECK',
    ]
    wiz_help = [
        {'prompt': 'Black Duck project name', 'vtype': 'string'},
        {'prompt': 'Black Duck version name', 'vtype': 'string'},
        {'prompt': 'Black Duck server URL', 'vtype': 'string_default', 'default': global_values.url},
        {'prompt': 'Black Duck API token', 'vtype': 'string_default', 'default': global_values.api},
        {'prompt': 'Trust BD Server certificate', 'vtype': 'yesno'},
        {'prompt': 'Recipe replacefile (used to remap recipes) path', 'vtype': 'file'},
        {'prompt': 'Do you want to run a CVE check to patch CVEs in the BD project which have been patched locally?',
         'vtype': 'yesno'},
    ]

    if ('BD_SERVER' in wlist or 'BD_API_TOKEN' in wlist) and not global_values.offline:
        if not input_yesno('Do you want to connect to a BD server to upload scan results?'):
            args.output_json = input_string('Output JSON file name (for manual upload)')
            global_values.offline = True
        else:
            global_values.offline = False
            wlist.append('BD_TRUST_CERT')

    if 'MANIFEST_FILE' in wlist or args.manifest == '' or (args.manifest != '' and not os.path.isdir(args.manifest)):
        # find manifest files
        args.manifest = input_filepattern("**/license.manifest", "'license.manifest'")

    if args.cve_check_file == '' and not args.no_cve_check:
        wlist.append('CVE_CHECK')

    if 'BBLAYERS_FILE' in wlist:
        if input_yesno('Yocto environment not configured - Do you want to search for and load the Yocto config?'):
            global_values.oefile = input_filepattern('**/oe-init*', 'OE environment file')
            args.bblayers_out = ''
            wlist.remove('BBLAYERS_FILE')
            if global_values.deploydir == '':
                global_values.deploydir = input_folder('Yocto deploy folder (usually poky/build/tmp/deploy)')
        else:
            args.bblayers_out = input_file(
                'Bitbake layers output file (output of command "bitbake-layers show-recipes")', False, True)

    if args.bblayers_out == '' and ('DEPLOY_DIR' in wlist or global_values.deploydir == ''):
        if global_values.deploydir != '' and os.path.isdir(global_values.deploydir):
            pass
        else:
            # get deploy folder
            global_values.deploydir = input_folder("Please enter the deploy folder (usually poky/build/tmp/deploy)")

    cvecheck = False
    for cat in wiz_categories:
        if global_values.offline and cat in ['BD_SERVER', 'BD_API_TOKEN', 'BD_TRUST_CERT']:
            continue

        if cat in wlist:
            val = ''
            if wiz_help[wiz_categories.index(cat)]['vtype'] == 'string':
                val = input_string(wiz_help[wiz_categories.index(cat)]['prompt'])
            elif wiz_help[wiz_categories.index(cat)]['vtype'] == 'string_default':
                val = input_string_default(wiz_help[wiz_categories.index(cat)]['prompt'],
                                           wiz_help[wiz_categories.index(cat)]['default'])
                # val = input_string(wiz_help[wiz_categories.index(cat)]['prompt'])
            elif wiz_help[wiz_categories.index(cat)]['vtype'] == 'yesno':
                val = input_yesno(wiz_help[wiz_categories.index(cat)]['prompt'])
            elif wiz_help[wiz_categories.index(cat)]['vtype'] == 'file':
                val = input_file(wiz_help[wiz_categories.index(cat)]['prompt'], False, True)

            if cat == 'PROJECT':
                args.project = val
            elif cat == 'VERSION':
                args.version = val
            elif cat == 'BD_SERVER':
                global_values.url = val
            elif cat == 'BD_API_TOKEN':
                global_values.api = val
            elif cat == 'BD_TRUST_CERT':
                args.blackduck_trust_cert = val
            elif cat == 'REPLACE_FILE':
                args.replacefile = val
            elif cat == 'CVE_CHECK':
                cvecheck = val

    if cvecheck:
        args.cve_check_file = input_filepattern("**/*.cve", "CVE check output file")

    repfile = input_file('Report file name', True, False)
    if repfile != '':
        args.report = repfile

    return
