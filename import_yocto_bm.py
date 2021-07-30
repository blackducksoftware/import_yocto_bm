import os
import json
import uuid
import datetime
import argparse
import sys
import platform
import re
import subprocess
import shutil
import time
import requests
# from blackduck.HubRestApi import HubInstance
from blackduck import Client


def check_args():
    global args
    global do_upload

    if args.project != "" and args.version != "":
        pass
    else:
        print("Please specify Black Duck project/version using -p and -v\nExiting")
        return False

    if not os.path.isdir(args.yocto_build_folder):
        print("Specified Yocto build folder '{}' does not exist\nExiting".format(args.yocto_build_folder))
        return False
    else:
        args.yocto_build_folder = os.path.abspath(args.yocto_build_folder)

    if args.cve_check_file != "" and args.no_cve_check:
        print("Options cve_check_file and no_cve_check cannot be specified together".format(args.cve_check_file))
        return False

    if args.cve_check_file != "" and not os.path.isfile(args.cve_check_file):
        print("CVE check output file '{}' does not exist\nExiting".format(args.cve_check_file))
        return False

    if args.cve_check_only and args.no_cve_check:
        print("Options --cve_check_only and --no_cve_check cannot be specified together")
        return False

    if args.output_json != "":
        print("CVE checking not supported with --output_json option - will be skipped")
        args.no_cve_check = True
        do_upload = False

    if args.manifest != "" and not os.path.isfile(args.manifest):
        print("Manifest file '{}' does not exist\nExiting".format(args.manifest))
        return False

    if args.replacefile != "" and not os.path.isfile(args.replacefile):
        print("Replacefile file '{}' does not exist\nExiting".format(args.replacefile))
        return False

    if args.kb_recipe_dir != '':
        if not os.path.isdir(args.kb_recipe_dir):
            print("KB data dir '{}' does not exist\nExiting".format(args.kb_recipe_dir))
            return False
        krfile = os.path.join(args.kb_recipe_dir, 'kb_recipes.json')
        kefile = os.path.join(args.kb_recipe_dir, 'kb_entries.json')

        if not os.path.isfile(krfile) or not os.path.isfile(kefile):
            print("KB data files do not exist in folder '{}'\nExiting".format(args.kb_recipe_dir))
            return False

    return True


def check_env():
    global args
    bd = None

    if args.output_json == '':
        url = os.environ.get('BLACKDUCK_URL')
        if args.blackduck_url:
            url = args.blackduck_url

        api = os.environ.get('BLACKDUCK_API_TOKEN')
        if args.blackduck_api_token != '':
            api = args.blackduck_api_token

        verify = True
        trustcert = os.environ.get('BLACKDUCK_TRUST_CERT')
        if trustcert == 'true':
            verify = False
        if args.blackduck_trust_cert:
            verify = False

        bd = Client(
            token=api,
            base_url=url,
            timeout=300,
            verify=verify  # TLS certificate verification
        )
        try:
            bd.list_resources()
        except Exception as exc:
            print('Unable to connect to BD server - {}'.format(str(exc)))
            return False, None

    if args.bblayers_out != '':
        return True, bd
    if platform.system() != "Linux":
        print("Please use this program on a Linux platform where Yocto project has been built\nExiting")
        return False, None

    # Check oe-pkgdata-util and bitbake commands are on PATH
    if shutil.which("bitbake") is None or shutil.which("bitbake-layers") is None:
        print(
            '''Please ensure Yocto project has been installed and environment has been set 
            (run 'source ooe-init-build-env)\nExiting''')
        return False, None
    return True, bd


def check_yocto_build_folder():
    global args
    # check Yocto build dir:
    # yocto_build_folders = [ "build", "meta", "bitbake" ]
    yocto_build_folders = ["conf", "cache", "tmp"]
    yocto_files = []

    if os.path.isdir(os.path.join(args.yocto_build_folder, "build")):
        args.yocto_build_folder = os.path.join(args.yocto_build_folder, "build")

    for d in yocto_build_folders:
        if not os.path.isdir(os.path.join(args.yocto_build_folder, d)):
            print(
                '''Project build folder {} does not appear to be a Yocto project folder which has been built ({} 
                folder missing)\nExiting'''.format(
                    args.yocto_build_folder, d))
            return False

    for f in yocto_files:
        if not os.path.isfile(os.path.join(args.yocto_build_folder, f)):
            print(
                '''Project build folder {} does not appear to be a Yocto project folder ({} file missing)\n
                Exiting'''.format(
                    args.yocto_build_folder, f))
            return False
    return True


def find_files():
    global args, licdir, args

    if args.bblayers_out != '':
        return True

    # Locate yocto files & folders
    if args.buildconf == "":
        args.buildconf = os.path.join(args.yocto_build_folder, "..", "meta", "conf", "bitbake.conf")
    if not os.path.isfile(args.buildconf):
        print("ERROR: Cannot locate bitbake conf file {}".format(args.buildconf))
        return False
    if args.localconf == "":
        args.localconf = os.path.join(args.yocto_build_folder, "conf", "local.conf")
    if not os.path.isfile(args.localconf):
        print("ERROR: Cannot locate local bitbake conf file {}".format(args.localconf))
        return False

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
        print("ERROR: Unable to read bitbake.conf file {}\n".format(args.buildconf) + str(e))
        return False

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
        print("ERROR: Unable to read local.conf file {}\n".format(args.localconf) + str(e))
        return False

    if tmpdir != "":
        tmpdir = tmpdir.replace('${TOPDIR}', args.yocto_build_folder)
        tmpdir = tmpdir.strip('"')
        tmpdir = os.path.expandvars(tmpdir)
    else:
        tmpdir = os.path.join(args.yocto_build_folder, "tmp")
    if not os.path.isdir(tmpdir):
        print("ERROR: TMPDIR does not exist {}\n".format(tmpdir))
        return False

    if deploydir != "":
        deploydir = deploydir.replace('${TMPDIR}', tmpdir)
        deploydir = deploydir.strip('"')
        deploydir = os.path.expandvars(deploydir)
    else:
        deploydir = os.path.join(args.yocto_build_folder, "tmp", "deploy")
    if not os.path.isdir(deploydir):
        print("ERROR: DEPLOYDIR does not exist {}\n".format(deploydir))
        return False

    if args.arch == "":
        args.arch = machine.strip('"')

    licdir = os.path.join(deploydir, "licenses")
    if args.manifest == "":
        manifestdir = ""
        if not os.path.isdir(licdir):
            print("License directory {} does not exist - has Yocto project been built?".format(licdir))
            return False
        for file in sorted(os.listdir(licdir)):
            if file.startswith(args.target + "-" + args.arch + "-"):
                manifestdir = os.path.join(licdir, file)

        manifestfile = os.path.join(manifestdir, "license.manifest")
        if not os.path.isfile(manifestfile):
            print(
                '''Build manifest file {} does not exist - either build Yocto project or use -m option to 
                specify build manifest file\nExiting'''.format(
                    manifestfile))
            return False
        else:
            print("Located manifest file {}".format(manifestfile))

        args.manifest = manifestfile

    if args.cve_check_file == "" and not args.no_cve_check:
        imgdir = os.path.join(deploydir, "images", args.arch)
        cvefile = ""
        for file in sorted(os.listdir(imgdir)):
            if file.startswith(args.target + "-" + args.arch + "-") and file.endswith("rootfs.cve"):
                cvefile = os.path.join(imgdir, file)

        if not os.path.isfile(cvefile):
            print("WARNING: CVE check file could not be located - CVE patch updates will be skipped")
        else:
            print("Located CVE check output file {}".format(cvefile))
            args.cve_check_file = cvefile

    return True


def get_projver(bd, pargs):
    params = {
        'q': "name:" + pargs.project,
        'sort': 'name',
    }
    projects = bd.get_resource('projects', params=params, items=False)

    if projects['totalCount'] == 0:
        print("ERROR: Project '{}' does not exist".format(pargs.project))
        sys.exit(2)

    projects = bd.get_resource('projects', params=params)
    for proj in projects:
        versions = bd.get_resource('versions', parent=proj, params=params)
        for ver in versions:
            if ver['versionName'] == pargs.version:
                return proj, ver
    print("ERROR: Version '{}' does not exist in project '{}'".format(pargs.project, pargs.version))
    sys.exit(2)


def proc_license_manifest(liclines):
    global recipes, packages

    print("- Working on recipes from license.manifest: ...")
    entries = 0
    ver = ''
    for line in liclines:
        arr = line.split(":")
        if len(arr) > 1:
            key = arr[0]
            value = arr[1].strip()
            if key == "PACKAGE NAME":
                packages.append(value)
            elif key == "PACKAGE VERSION":
                ver = value
            elif key == "RECIPE NAME":
                entries += 1
                if value not in recipes.keys():
                    recipes[value] = ver
    if entries == 0:
        return False
    print("	Identified {} recipes from {} packages".format(len(recipes), entries))
    return True


def proc_layers_in_recipes():
    global layers, recipe_layer, args

    if args.bblayers_out != '':
        if not os.path.isfile(args.bblayers_out):
            print("ERROR: Cannot open bblayers file {} specified by --bblayers_out".format(args.bblayers_out))
            sys.exit(3)
        r = open(args.bblayers_out, "r")
        lines = r.read().splitlines()
        r.close()
    else:
        print("- Identifying layers for recipes ...")
        output = subprocess.check_output(['bitbake-layers', 'show-recipes', '*'], stderr=subprocess.STDOUT)
        mystr = output.decode("utf-8").strip()
        lines = mystr.splitlines()

    rec = ""
    bstart = False
    for rline in lines:
        if bstart:
            if rline.endswith(":"):
                arr = rline.split(":")
                rec = arr[0]
            elif rec != "":
                arr = rline.split()
                if len(arr) > 1:
                    layer = arr[0]
                    ver = arr[1]
                    # if rec in recipes.keys():
                    #     recipes[rec] = ver
                    # if layer not in layers:
                    #     layers.append(layer)
                    if rec in recipes.keys() and recipes[rec] == ver:
                        recipe_layer[rec] = layer
                        if layer not in layers:
                            layers.append(layer)
                rec = ""
        elif rline.endswith(": ==="):
            bstart = True
    print("	Discovered {} layers".format(len(layers)))


def proc_recipe_revisions():
    global licdir, recipes, args

    print("- Identifying recipe revisions: ...")
    for recipe in recipes.keys():
        if recipes[recipe].find("AUTOINC") != -1:
            # recipes[recipe] = recipes[recipe].split("AUTOINC")[0] + "X-" + recipes[recipe].split("-")[-1]
            recipes[recipe] = recipes[recipe].split("AUTOINC")[0] + "X"
        if recipes[recipe].find("+svn") != -1:
            # recipes[recipe] = recipes[recipe].split("+svn")[0] + "+svnX" + recipes[recipe].split("-")[-1]
            recipes[recipe] = recipes[recipe].split("+svn")[0] + "+svnX"
        if args.bblayers_out != '':
            recipes[recipe] += "-r0"
            continue

        recipeinfo = os.path.join(licdir, recipe, "recipeinfo")
        if os.path.isfile(recipeinfo):
            try:
                r = open(recipeinfo, "r")
                reclines = r.readlines()
                r.close()
            except Exception as e:
                print("ERROR: unable to open recipeinfo file {}\n".format(recipeinfo) + str(e))
                sys.exit(3)
            for line in reclines:
                if line.find("PR:") != -1:
                    arr = line.split(":")
                    rev = arr[1].strip()
                    recipes[recipe] += "-" + rev
        else:
            print("ERROR: Recipeinfo file {} does not exist\n".format(recipeinfo))
            sys.exit(3)


def proc_layers():
    global proj_rel, comps_layers, layers, recipes, recipe_layer
    global rep_layers

    print("- Processing layers: ...")
    # proj_rel is for the project relationship (project to layers)
    for layer in layers:
        # if layer in rep_layers.keys():
        #     rep_layer = rep_layers[layer]
        # else:
        #     rep_layer = layer
        proj_rel.append(
            {
                # "related": "http:yocto/" + rep_layer + "/1.0",
                "related": "http:yocto/" + layer + "/1.0",
                "relationshipType": "DYNAMIC_LINK"
            }
        )
        layer_rel = []
        for recipe in recipes.keys():
            if recipe in recipe_layer.keys() and recipe_layer[recipe] == layer:
                # print("DEBUG: " + recipe)
                ver = recipes[recipe]

                # DEBUG - replacefile
                # rec_layer = rep_layer
                # if recipe in rep_recipes.keys():
                #     recipever_string = rep_recipes[recipe] + "/" + ver
                # elif recipe + "/" + ver in rep_recipes.keys():
                #     recipever_string = rep_recipes[recipe + "/" + ver]
                # elif layer + "/" + recipe in rep_recipes.keys():
                #     rec_layer = rep_recipes[rep_layer + "/" + recipe].split("/")[0]
                #     slash = rep_recipes[rep_layer + "/" + recipe].find("/") + 1
                #     recipever_string = rep_recipes[rep_layer + "/" + recipe][slash:]
                # elif layer + "/" + recipe + "/" + ver in rep_recipes.keys():
                #     rec_layer = rep_recipes[rep_layer + "/" + recipe + "/" + ver].split("/")[0]
                #     slash = rep_recipes[rep_layer + "/" + recipe + "/" + ver].find("/") + 1
                #     recipever_string = rep_recipes[rep_layer + "/" + recipe + "/" + ver][slash:]
                # else:
                #     recipever_string = recipe + "/" + ver
                recipever_string = recipe + "/" + ver

                layer_rel.append(
                    {
                        # "related": "http:yocto/" + rec_layer + "/" + recipever_string,
                        "related": "http:yocto/" + layer + "/" + recipever_string,
                        "relationshipType": "DYNAMIC_LINK"
                    }
                )

        comps_layers.append({
            # "@id": "http:yocto/" + rep_layer + "/1.0",
            "@id": "http:yocto/" + layer + "/1.0",
            "@type": "Component",
            "externalIdentifier": {
                "externalSystemTypeId": "@yocto",
                # "externalId": rep_layer,
                "externalId": layer,
                "externalIdMetaData": {
                    "forge": {
                        "name": "yocto",
                        "separator": "/",
                        "usePreferredNamespaceAlias": True
                    },
                    "pieces": [
                        # rep_layer,
                        layer,
                        "1.0"
                    ],
                    "prefix": "meta"
                }
            },
            "relationship": layer_rel
        })


def proc_recipes():
    global recipes, recipe_layer, comps_recipes
    global rep_recipes, rep_layers

    print("- Processing recipes: ...")
    for recipe in recipes.keys():
        ver = recipes[recipe]

        if recipe in recipe_layer.keys():
            layer = recipe_layer[recipe]
        #     if recipe_layer[recipe] in rep_layers.keys():
        #         layer_string = rep_layers[recipe_layer[recipe]]
        #     else:
        #         layer_string = recipe_layer[recipe]
        #     layer_string = recipe_layer[recipe]

            # if recipe in rep_recipes.keys():
            #     recipever_string = rep_recipes[recipe] + "/" + ver
            # elif recipe + "/" + ver in rep_recipes.keys():
            #     recipever_string = rep_recipes[recipe + "/" + ver]
            # elif layer + "/" + recipe in rep_recipes.keys():
            #     layer_string = rep_recipes[layer + "/" + recipe].split("/")[0]
            #     slash = rep_recipes[layer + "/" + recipe].find("/") + 1
            #     recipever_string = rep_recipes[layer + "/" + recipe][slash:]
            # elif layer + "/" + recipe + "/" + ver in rep_recipes.keys():
            #     layer_string = rep_recipes[layer + "/" + recipe + "/" + ver].split("/")[0]
            #     slash = rep_recipes[layer + "/" + recipe + "/" + ver].find("/") + 1
            #     recipever_string = rep_recipes[layer + "/" + recipe + "/" + ver][slash:]
            # else:
            #     recipever_string = recipe + "/" + ver
            recipever_string = recipe + "/" + ver

            # if recipe + "/" + ver != recipever_string:
            #     print(
            #         "INFO: Replaced layer/recipe {}/{} with {}/{} from replacefile".format(
            #             layer, recipe, layer_string, recipever_string))

            comps_recipes.append(
                {
                    "@id": "http:yocto/" + layer + "/" + recipever_string,
                    "@type": "Component",
                    "externalIdentifier": {
                        "externalSystemTypeId": "@yocto",
                        "externalId": layer + "/" + recipever_string,
                        "externalIdMetaData": {
                            "forge": {
                                "name": "yocto",
                                "separator": "/",
                                "usePreferredNamespaceAlias": True
                            },
                            "pieces": [
                                recipever_string.replace("/", ",")
                            ],
                            "prefix": layer
                        }
                    },
                    "relationship": []
                })


def proc_yocto_project(manfile):
    global args
    global bdio
    global proj
    global ver
    global comps_layers
    global comps_recipes
    global packages
    global recipes
    global comps_recipes
    global recipe_layer
    global layers
    global proj_rel
    global comps_layers
    global rep_layers
    global rep_recipes
    global do_upload

    try:
        i = open(manfile, "r")
    except Exception as e:
        print('ERROR: Unable to open input manifest file {}\n'.format(manfile) + str(e))
        sys.exit(3)

    try:
        liclines = i.readlines()
        i.close()
    except Exception as e:
        print('ERROR: Unable to read license.manifest file {} \n'.format(manfile) + str(e))
        sys.exit(3)

    print("\nProcessing Bitbake project:")
    if not proc_license_manifest(liclines):
        sys.exit(3)
    proc_layers_in_recipes()
    proc_recipe_revisions()
    if not args.no_kb_check:
        check_recipes(args.kb_recipe_dir)
    proc_layers()
    proc_recipes()

    # proj_rel is for the project relationship (project to layers)
    if args.code_location_prefix != '':
        clprefix = args.code_location_prefix + '-'
    else:
        clprefix = ''

    u = uuid.uuid1()

    mytime = datetime.datetime.now()
    bdio_header = {
        "specVersion": "1.1.0",
        "spdx:name": clprefix + args.project + "/" + args.version + " yocto/bom",
        "creationInfo": {
            "spdx:creator": [
                "Tool: Detect-6.3.0",
                "Tool: IntegrationBdio-21.0.1"
            ],
            "spdx:created": mytime.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        },
        "@id": "uuid:" + str(u),
        "@type": "BillOfMaterials",
        "relationship": []
    }

    bdio_project = {
        "name": args.project,
        "revision": args.version,
        "@id": "http:yocto/" + args.project + "/" + args.version,
        "@type": "Project",
        "externalIdentifier": {
            "externalSystemTypeId": "@yocto",
            "externalId": "yocto/" + args.project + "/" + args.version,
            "externalIdMetaData": {
                "forge": {
                    "name": "yocto",
                    "separator": ":",
                    "usePreferredNamespaceAlias": True
                },
                "pieces": [
                    args.project,
                    args.version
                ],
                "prefix": ""
            }
        },
        "relationship": proj_rel
    }

    bdio = [bdio_header, bdio_project, comps_layers, comps_recipes]
    if not write_bdio(bdio):
        sys.exit(3)


def write_bdio(bdio):
    global args

    if args.output_json != "":
        try:
            o = open(args.output_json, "w")
            o.write(json.dumps(bdio, indent=4))
            o.close()
            print("\nJSON project file written to {} - must be manually uploaded".format(args.output_json))
        except Exception as e:
            print("ERROR: Unable to write output JSON file {}\n".format(args.output_json) + str(e))
            return False

    else:
        import tempfile
        try:
            with tempfile.NamedTemporaryFile(suffix=".jsonld", delete=False) as o:
                args.output_json = o.name
                o.write(json.dumps(bdio, indent=4).encode())
                o.close()
        except Exception as e:
            print("ERROR: Unable to write temporary output JSON file\n" + str(e))
            return False

    return True


def upload_json(bd, filename):

    url = bd.base_url + "/api/scan/data/?mode=replace"
    headers = {
        'X-CSRF-TOKEN': bd.session.auth.csrf_token,
        'Authorization': 'Bearer ' + bd.session.auth.bearer_token,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    if filename.endswith('.json') or filename.endswith('.jsonld'):
        headers['Content-Type'] = 'application/ld+json'
        with open(filename, "r") as f:
            response = requests.post(url, headers=headers, data=f)
    elif filename.endswith('.bdio'):
        headers['Content-Type'] = 'application/vnd.blackducksoftware.bdio+zip'
        with open(filename, "rb") as f:
            response = requests.post(url, headers=headers, data=f)
    else:
        raise Exception("Unknown file type")
    if response.status_code == 201:
        return True
    else:
        return False


def patch_vuln(hub, comp):
    status = "PATCHED"
    comment = "Patched by bitbake recipe"

    try:
        # vuln_name = comp['vulnerabilityWithRemediation']['vulnerabilityName']

        comp['remediationStatus'] = status
        comp['remediationComment'] = comment
        result = hub.execute_put(comp['_meta']['href'], data=comp)
        if result.status_code != 202:
            return False

    except Exception as e:
        print("ERROR: Unable to update vulnerabilities via API\n" + str(e))
        return False

    return True


def process_patched_cves(hub, version, vuln_list):
    global args

    try:
        vulnerable_components_url = hub.get_link(version, "vulnerable-components") + "?limit=9999"
        custom_headers = {'Accept': 'application/vnd.blackducksoftware.bill-of-materials-6+json'}
        response = hub.execute_get(vulnerable_components_url, custom_headers=custom_headers)
        vulnerable_bom_components = response.json().get('items', [])

        count = 0

        for comp in vulnerable_bom_components:
            if comp['vulnerabilityWithRemediation']['source'] == "NVD":
                if comp['vulnerabilityWithRemediation']['vulnerabilityName'] in vuln_list:
                    if patch_vuln(hub, comp):
                        print("		Patched {}".format(comp['vulnerabilityWithRemediation']['vulnerabilityName']))
                        count += 1
            elif comp['vulnerabilityWithRemediation']['source'] == "BDSA":
                vuln_url = hub.get_apibase() + "/vulnerabilities/" + comp['vulnerabilityWithRemediation'][
                    'vulnerabilityName']
                custom_headers = {'Accept': 'application/vnd.blackducksoftware.vulnerability-4+json'}
                resp = hub.execute_get(vuln_url, custom_headers=custom_headers)
                vuln = resp.json()
                # print(json.dumps(vuln, indent=4))
                for x in vuln['_meta']['links']:
                    if x['rel'] == 'related-vulnerability':
                        if x['label'] == 'NVD':
                            cve = x['href'].split("/")[-1]
                            if cve in vuln_list:
                                if patch_vuln(hub, comp):
                                    print("		Patched " + vuln['name'] + ": " + cve)
                                    count += 1

    except Exception as e:
        print("ERROR: Unable to get components from project via API\n" + str(e))
        return False

    print("- {} CVEs marked as patched in project '{}/{}'".format(count, args.project, args.version))
    return True


def wait_for_bom_completion(bd, ver):
    # Check job status
    try:
        links = ver['_meta']['links']
        link = next((item for item in links if item["rel"] == "bom-status"), None)

        href = link['href']
        headers = {'Accept': 'application/vnd.blackducksoftware.internal-1+json'}
        # resp = hub.execute_get(href, custom_headers=custom_headers)
        resp = bd.get_json(href, headers=headers)

        loop = 0
        uptodate = resp['upToDate']
        while not uptodate and loop < 80:
            time.sleep(15)
            # resp = hub.execute_get(href, custom_headers=custom_headers)
            resp = bd.get_json(href, headers=headers)
            uptodate = resp['upToDate']
            loop += 1
    except Exception as e:
        print("ERROR: {}".format(str(e)))
        return False

    if uptodate:
        return True
    else:
        return False


def wait_for_scans(bd, ver):
    links = ver['_meta']['links']
    link = next((item for item in links if item["rel"] == "codelocations"), None)

    href = link['href']

    time.sleep(10)
    wait = True
    loop = 0
    while wait and loop < 20:
        custom_headers = {'Accept': 'application/vnd.blackducksoftware.internal-1+json'}
        resp = bd.execute_get(href, custom_headers=custom_headers)
        for cl in resp.json()['items']:
            if 'status' in cl:
                status_list = cl['status']
                for status in status_list:
                    if status['operationNameCode'] == "ServerScanning":
                        if status['status'] == "COMPLETED":
                            wait = False
        if wait:
            time.sleep(15)
            loop += 1

    return not wait


def proc_replacefile():
    global args
    global rep_layers, rep_recipes

    print("- Processing replacefile {}: ...".format(args.replacefile))
    try:
        r = open(args.replacefile, "r")
        for line in r:
            # if re.search('^LAYER ', line):
            #     rep_layers[line.split()[1]] = line.split()[2]
            if re.search('^RECIPE ', line):
                origrec = line.split()[1]
                reprec = line.split()[2]
                if len(origrec.split('/')) != 3 or len(reprec.split('/')) != 3 :
                    print('Ignored line {} - complete layer/recipe/revision required'.format(line))
                    continue
                rep_recipes[line.split()[1]] = line.split()[2]
            else:
                print('Ignored line {}'.format(line))
        r.close()
    except Exception as e:
        print("ERROR: Unable to read replacefile file {}\n".format(args.replacefile) + str(e))
        return False

    print("	{} replace entries processed".format(len(rep_layers) + len(rep_recipes)))
    return True


def get_kbrecipelist(kbrecdir):
    import requests

    print("- Checking recipes against Black Duck KB ...")

    if kbrecdir != "":
        krfile = os.path.join(kbrecdir, 'kb_recipes.json')
        kefile = os.path.join(kbrecdir, 'kb_entries.json')

        try:
            with open(krfile) as kr:
                kbrecipes = json.load(kr)
            with open(kefile) as ke:
                kbentries = json.load(ke)

        except Exception as e:
                return None, None
    else:
        print("	Downloading KB recipes ...")

        url = 'https://raw.github.com/blackducksoftware/import_yocto_bm/master/data/kb_recipes.json'
        r = requests.get(url)

        if r.status_code != 200:
            print(
                '''Unable to download KB recipe data from Github. 
                Consider downloading data folder manually and using the --kb_recipe_dir option.''')
            return None, None
        # klines = r.text.split("\n")
        kbrecipes = r.json()

        url = 'https://raw.github.com/blackducksoftware/import_yocto_bm/master/data/kb_entries.json'
        r = requests.get(url)

        if r.status_code != 200:
            print(
                '''Unable to download KB recipe data from Github. 
                Consider downloading data folder manually and using the --kb_recipe_dir option.''')
            return None, None
        # klines = r.text.split("\n")
        kbentries = r.json()

    # print("	Reading KB recipes ...")

    # for kline in klines:
    #     arr = kline.rstrip().split('/')
    #     if len(arr) == 3:
    #         layer = arr[0]
    #         recipe = arr[1]
    #         ver = arr[2]
    #         if ver == '':
    #             continue
    #         if layer not in kblayers:
    #             kblayers.append(layer)
    #
    #         if recipe not in kbrecipes.keys():
    #             kbrecipes[recipe] = [layer + "/" + ver]
    #         elif layer + "/" + ver not in kbrecipes[recipe]:
    #             kbrecipes[recipe].append(layer + "/" + ver)
    #
    #         if kline not in kbentries:
    #             kbentries.append(kline)
    #
    # print("	Processed {} recipes from KB".format(len(kbentries)))
    #
    # with open('kb_recipes.json', "w") as f:
    #     f.write(json.dumps(kbrecipes, indent=4))
    # with open('kb_entries.json', "w") as f:
    #     f.write(json.dumps(kbentries, indent=4))

    # with open('kb_recipes.json') as kr:
    #     kbrecipes = json.load(kr)
    #
    # with open('kb_entries.json') as ke:
    #     kbentries = json.load(ke)

    print("	Loaded {} recipes from KB".format(len(kbentries)))

    return kbrecipes, kbentries


def check_recipes(kbrecdir):
    global recipes, recipe_layer
    global rep_layers, rep_recipes

    kbrecipes, kbentries = get_kbrecipelist(kbrecdir)

    keys = ['OK', 'REPLACED', 'REPLACED_NOREVISION', 'REPLACED_NOLAYER+REVISION', 'NOTREPLACED_NOVERSION',
            'NOTREPLACED_NOLAYER+VERSION', 'MISSING', 'SKIPPED']
    report = {}
    for key in keys:
        report[key] = []

    layer = ''
    origcomp = ''
    for recipe in recipes.keys():
        # print(recipe + "/" + recipes[recipe])
        ver = recipes[recipe]

        if recipe in recipe_layer.keys():
            origlayer = recipe_layer[recipe]
            layer = origlayer
            comp = origlayer + "/" + recipe + "/" + recipes[recipe]
            origcomp = comp

            # newlayer_string = layer
            # if recipe in rep_recipes.keys():
            #     newrecipever_string = rep_recipes[recipe] + "/" + ver
            # elif recipe + "/" + ver in rep_recipes.keys():
            #     newrecipever_string = rep_recipes[recipe + "/" + ver]
            # elif layer + "/" + recipe in rep_recipes.keys():
            #     newlayer_string = rep_recipes[layer + "/" + recipe].split("/")[0]
            #     slash = rep_recipes[layer + "/" + recipe].find("/") + 1
            #     newrecipever_string = rep_recipes[layer + "/" + recipe][slash:]
            # elif layer + "/" + recipe + "/" + ver in rep_recipes.keys():
            #     newlayer_string = rep_recipes[layer + "/" + recipe + "/" + ver].split("/")[0]
            #     slash = rep_recipes[layer + "/" + recipe + "/" + ver].find("/") + 1
            #     newrecipever_string = rep_recipes[layer + "/" + recipe + "/" + ver][slash:]
            # else:
            #     newrecipever_string = recipe + "/" + ver
            # comp = newlayer_string + "/" + newrecipever_string

            if comp in rep_recipes.keys():
                comp = rep_recipes[comp]

            if comp in kbentries:
                # Component exists in KB
                report['OK'].append(comp)
                print('	- OK       - Component {}/{}: Mapped directly'.format(
                    recipe, recipes[recipe]))
                continue
        else:
            print('	- SKIPPED  - Component {}/{}: Recipe missing from bitbake-layers output'.format(
                recipe, recipes[recipe]))
            report['SKIPPED'].append(comp)
            continue

        # No exact match found in KB list
        val = ver.rfind('-r')
        ver_norev = ''
        if val > 0:
            ver_norev = ver[:val]

        if recipe in kbrecipes.keys():
            # recipe exists in KB
            kbrecvers = []
            kbreclayers = []
            for kbentry in kbrecipes[recipe]:
                arr = kbentry.split("/")
                kbreclayers.append(arr[0])
                kbrecvers.append(arr[1])

                if layer != arr[0] and ver == arr[1]:
                    # Recipe and version exist in KB - layer is different
                    print("	- REPLACED - Component {}: Recipe and version exist in KB, but not within the layer '{}' - \
replaced with '{}/{}/{}' from KB".format(origcomp, layer, arr[0], recipe, ver))
                    recipe_layer[recipe] = arr[0]
                    report['REPLACED'].append("ORIG={} REPLACEMENT={}/{}/{}".format(origcomp, arr[0], recipe, ver))
                    break
                elif layer == arr[0] and ver_norev == arr[1]:
                    # Layer, Recipe and version without rev exist in KB
                    print("	- REPLACED - Component {}: Layer, Recipe and version w/o revision in KB - replaced \
with '{}/{}/{}' from KB".format(comp, arr[0], recipe, ver_norev))
                    recipe_layer[recipe] = arr[0]
                    recipes[recipe] = ver_norev
                    report['REPLACED'].append("ORIG={} REPLACEMENT={}/{}/{}".format(
                        origcomp, arr[0], recipe, ver_norev))
                    break
                elif layer != arr[0] and ver_norev == arr[1]:
                    # Recipe and version exist in KB - layer is different
                    print("	- REPLACED - Component {}: Recipe and version exist in KB, but not within the layer '{}' - \
replaced with '{}/{}/{}' from KB".format(origcomp, layer, arr[0], recipe, ver_norev))
                    recipe_layer[recipe] = arr[0]
                    recipes[recipe] = ver_norev
                    report['REPLACED'].append("ORIG={} REPLACEMENT={}/{}/{}".format(
                        origcomp, arr[0], recipe, ver_norev))
                    break
            else:
                # Recipe exists in KB but Layer+Version or Version does not
                rev = ver.split("-r")[-1]
                if len(ver.split("-r")) > 1 and rev.isdigit():
                    ver_without_rev = ver[0:len(ver) - len(rev) - 2]
                    for kbver in kbrecvers:
                        kbrev = kbver.split("-r")[-1]
                        if len(kbver.split("-r")) > 1 and kbrev.isdigit():
                            kbver_without_rev = kbver[0:len(kbver) - len(kbrev) - 2]
                            if ver_without_rev == kbver_without_rev:
                                # Found KB version with a different revision
                                if layer == kbreclayers[kbrecvers.index(kbver)]:
                                    print("	- REPLACED - Component {}: Layer, recipe and version exist in KB, but \
revision does not - replaced with '{}/{}/{}' from KB".format(origcomp, kbreclayers[kbrecvers.index(kbver)], recipe, kbver))
                                    recipes[recipe] = kbver
                                    report['REPLACED_NOREVISION'].append("ORIG={} REPLACEMENT={}/{}/{}".format(
                                        origcomp, kbreclayers[kbrecvers.index(kbver)], recipe, kbver))
                                else:
                                    print("	- REPLACED - Component {}: Recipe and version exist in KB, but revision \
and layer do not - replaced with '{}/{}/{}' from KB".format(comp, kbreclayers[kbrecvers.index(kbver)], recipe, kbver))
                                    recipe_layer[recipe] = kbreclayers[kbrecvers.index(kbver)]
                                    recipes[recipe] = kbver
                                    report['REPLACED_NOLAYER+REVISION'].append("ORIG={} REPLACEMENT={}/{}/{}".format(
                                        origcomp, kbreclayers[kbrecvers.index(kbver)], recipe, kbver))
                                break
                    else:
                        if layer == kbreclayers[kbrecvers.index(kbver)]:
                            # Recipe exists in layer within KB, but version does not
                            reclist = []
                            for l, r in zip(kbreclayers, kbrecvers):
                                if len(l) > 0 and len(r) > 0:
                                    reclist.append(l + '/' + recipe + '/' + r)
                            report['NOTREPLACED_NOVERSION'].append(
                                "ORIG={} Check layers/recipes in KB - Available versions={}".format(origcomp, reclist))
                            print("	- SKIPPED  - Component {}: Recipe exists in KB within the layer but version does \
not - consider using --repfile with a version replacement (available versions {})".format(origcomp, reclist))
                            continue
                        else:
                            # Recipe exists within KB, but layer and version do not
                            reclist = []
                            for l, r in zip(kbreclayers, kbrecvers):
                                if len(l) > 0 and len(r) > 0:
                                    reclist.append(l + '/' + recipe + '/' + r)
                            print("	- SKIPPED  - Component {}: Recipe exists in KB but layer and version do not - \
consider using --repfile with a version replacement (available versions {})".format(origcomp, reclist))
                            report['NOTREPLACED_NOLAYER+VERSION'].append(
                                "ORIG={} Check layers/recipes in KB - Available versions={}".format(
                                    origcomp, reclist))
                            continue
            continue

        print("	- SKIPPED  - Component {}: missing from KB - will not be mapped in Black Duck project".format(origcomp))
        report['MISSING'].append(origcomp)

    print("	Processed {} recipes from Yocto project ({} mapped, {} not mapped, {} skipped) ...".format(
        len(recipes), len(report['OK']) + len(report['REPLACED']) + len(report['REPLACED_NOREVISION']) +
        len(report['REPLACED_NOLAYER+REVISION']), len(report['NOTREPLACED_NOVERSION']) +
        len(report['NOTREPLACED_NOLAYER+VERSION']) + len(report['MISSING']), len(report['SKIPPED']))
    )
    if args.report != '':
        try:
            repfile = open(args.report, "w")
            for key in keys:
                for rep in report[key]:
                    repfile.write(key + ':' + rep + '\n')
        except Exception as e:
            return
        finally:
            repfile.close()
            print(' Report file {} written containing list of mapped layers/recipes.'.format(args.report))

    return


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

args = parser.parse_args()

if args.bblayers_out != '':
    args.no_cve_check = True

bdio = []
proj = args.project
ver = args.version
comps_layers = []
comps_recipes = []
packages = []
recipes = {}
recipe_layer = {}
layers = []
proj_rel = []
rep_layers = {}
rep_recipes = {}
do_upload = True
licdir = ''


def main():
    global args
    global bdio
    global proj
    global ver
    global comps_layers
    global comps_recipes
    global packages
    global recipes
    global comps_recipes
    global recipe_layer
    global layers
    global proj_rel
    global comps_layers
    global rep_layers
    global rep_recipes
    global do_upload
    bd = None

    print("Yocto build manifest import into Black Duck Utility v1b.15")
    print("---------------------------------------------------------\n")

    if not check_args():
        sys.exit(1)

    status, bd = check_env()
    if not status or not find_files():
        sys.exit(1)

    if args.manifest == "":
        if not check_yocto_build_folder():
            sys.exit(1)
        elif os.path.isabs(args.yocto_build_folder):
            print("Working on Yocto build folder '{}'\n".format(args.yocto_build_folder))
        else:
            print("Working on Yocto build folder '{}' (Absolute path '{}')\n".format(
                args.yocto_build_folder, os.path.abspath(args.yocto_build_folder)))

    if args.replacefile != "":
        if not proc_replacefile():
            sys.exit(3)

    if not args.cve_check_only:
        proc_yocto_project(args.manifest)

        if do_upload:
            print("\nUploading scan to Black Duck server ...")
            if upload_json(bd, args.output_json):
                print("Scan file uploaded successfully\nBlack Duck project '{}/{}' created.".format(
                    args.project, args.version))
            else:
                print("ERROR: Unable to upload scan file")
                sys.exit(3)

    if args.cve_check_file != "" and not args.no_cve_check:

        print("\nProcessing CVEs ...")

        if not args.cve_check_only:
            print("Waiting for Black Duck server scan completion before continuing ...")
            # Need to wait for scan to process into queue - sleep 15
            time.sleep(30)

        try:
            print("- Reading Black Duck project ...")
            proj, ver = get_projver(bd, args)
        except Exception as e:
            print("ERROR: Unable to get project version from API\n" + str(e))
            sys.exit(3)

        if not wait_for_scans(bd, ver):
            print("ERROR: Unable to determine scan status")
            sys.exit(3)

        if not wait_for_bom_completion(bd, ver):
            print("ERROR: Unable to determine BOM status")
            sys.exit(3)

        print("- Loading CVEs from cve_check log ...")

        try:
            cvefile = open(args.cve_check_file, "r")
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
                        if pkgvuln['package'] in packages:
                            cves_in_bm += 1
                    pkgvuln = {}

        print("      {} total patched CVEs identified".format(len(patched_vulns)))
        if not args.cve_check_only:
            print(
                '''      {} Patched CVEs within packages in build manifest (including potentially mismatched 
            CVEs which should be ignored)'''.format(
                    cves_in_bm))
        if len(patched_vulns) > 0:
            process_patched_cves(bd, ver, patched_vulns)
    print("Done")


if __name__ == "__main__":
    main()
