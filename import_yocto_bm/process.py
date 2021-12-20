import os
import uuid
import datetime
import sys
import re
import subprocess

from import_yocto_bm import global_values
from import_yocto_bm import utils
from import_yocto_bm import config


def proc_license_manifest(liclines):
    print("- Working on recipes from license.manifest: ...")
    entries = 0
    ver = ''
    for line in liclines:
        arr = line.split(":")
        if len(arr) > 1:
            key = arr[0]
            value = arr[1].strip()
            if key == "PACKAGE NAME":
                global_values.packages_list.append(value)
            elif key == "PACKAGE VERSION":
                ver = value
            elif key == "RECIPE NAME":
                entries += 1
                if value not in global_values.recipes_dict.keys():
                    global_values.recipes_dict[value] = ver
    if entries == 0:
        return False
    print("	Identified {} recipes from {} packages".format(len(global_values.recipes_dict), entries))
    return True


def proc_layers_in_recipes():
    if config.args.bblayers_out != '':
        if not os.path.isfile(config.args.bblayers_out):
            print("ERROR: Cannot open bblayers file {} specified by --bblayers_out".format(config.args.bblayers_out))
            sys.exit(3)
        r = open(config.args.bblayers_out, "r")
        lines = r.read().splitlines()
        r.close()
    else:
        print("- Identifying layers for recipes ...")
        if global_values.oefile == '':
            output = subprocess.check_output(['bitbake-layers', 'show-recipes'], stderr=subprocess.STDOUT)
        else:
            output = subprocess.check_output(['bash', '-c', 'source ' + global_values.oefile +
                                              ' && bitbake-layers show-recipes'], stderr=subprocess.STDOUT)

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
                    # print(ver)
                    # if ver.find(':') >= 0:
                    #     print('found')
                    if rec in global_values.recipes_dict.keys():
                        if global_values.recipes_dict[rec] == ver:
                            global_values.recipe_layer_dict[rec] = layer
                            if layer not in global_values.layers_list:
                                global_values.layers_list.append(layer)
                        elif ver.find(':') >= 0:
                            # version does not match exactly
                            # check for epoch
                            tempver = ver.split(':')[1]
                            if global_values.recipes_dict[rec] == tempver:
                                # version includes epoch:
                                # update version in dict
                                global_values.recipes_dict[rec] = ver
                                global_values.recipe_layer_dict[rec] = layer
                                if layer not in global_values.layers_list:
                                    global_values.layers_list.append(layer)
                                    
                rec = ""
        elif rline.endswith(": ==="):
            bstart = True
    print("	Discovered {} layers".format(len(global_values.layers_list)))


def proc_recipe_revisions():
    print("- Identifying recipe revisions: ...")
    for recipe in global_values.recipes_dict.keys():
        if global_values.recipes_dict[recipe].find("AUTOINC") != -1:
            # recipes[recipe] = recipes[recipe].split("AUTOINC")[0] + "X-" + recipes[recipe].split("-")[-1]
            global_values.recipes_dict[recipe] = global_values.recipes_dict[recipe].split("AUTOINC")[0] + "X"
        if global_values.recipes_dict[recipe].find("+svn") != -1:
            # recipes[recipe] = recipes[recipe].split("+svn")[0] + "+svnX" + recipes[recipe].split("-")[-1]
            global_values.recipes_dict[recipe] = global_values.recipes_dict[recipe].split("+svn")[0] + "+svnX"
        if config.args.bblayers_out != '':
            global_values.recipes_dict[recipe] += "-r0"
            continue

        recipeinfo = os.path.join(global_values.deploydir, 'licenses', recipe, "recipeinfo")
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
                    global_values.recipes_dict[recipe] += "-" + rev
                    break
        else:
            print("WARNING: Recipeinfo file {} does not exist - assuming no revision\n".format(recipeinfo))


def proc_layers():
    print("- Processing layers: ...")
    # proj_rel is for the project relationship (project to layers)
    for layer in global_values.layers_list:
        # if layer in rep_layers.keys():
        #     rep_layer = rep_layers[layer]
        # else:
        #     rep_layer = layer
        global_values.bdio_proj_rel_list.append(
            {
                # "related": "http:yocto/" + rep_layer + "/1.0",
                "related": "http:yocto/" + layer + "/1.0",
                "relationshipType": "DYNAMIC_LINK"
            }
        )
        bdio_layer_rel = []
        for recipe in global_values.recipes_dict.keys():
            if recipe in global_values.recipe_layer_dict.keys() and global_values.recipe_layer_dict[recipe] == layer:
                # print("DEBUG: " + recipe)
                ver = global_values.recipes_dict[recipe]

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

                bdio_layer_rel.append(
                    {
                        # "related": "http:yocto/" + rec_layer + "/" + recipever_string,
                        "related": "http:yocto/" + layer + "/" + recipever_string,
                        "relationshipType": "DYNAMIC_LINK"
                    }
                )

        global_values.bdio_comps_layers.append({
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
            "relationship": bdio_layer_rel
        })


def proc_recipes():
    print("- Processing recipes: ...")
    for recipe in global_values.recipes_dict.keys():
        ver = global_values.recipes_dict[recipe]

        if recipe in global_values.recipe_layer_dict.keys():
            layer = global_values.recipe_layer_dict[recipe]
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

            global_values.bdio_comps_recipes.append(
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
    if not config.args.no_kb_check:
        utils.check_recipes(config.args.kb_recipe_dir)
    proc_layers()
    proc_recipes()

    # proj_rel is for the project relationship (project to layers)
    if config.args.code_location_prefix != '':
        clprefix = config.args.code_location_prefix + '-'
    else:
        clprefix = ''

    u = uuid.uuid1()

    mytime = datetime.datetime.now()
    bdio_header = {
        "specVersion": "1.1.0",
        "spdx:name": clprefix + config.args.project + "/" + config.args.version + " yocto/bom",
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
        "name": config.args.project,
        "revision": config.args.version,
        "@id": "http:yocto/" + config.args.project + "/" + config.args.version,
        "@type": "Project",
        "externalIdentifier": {
            "externalSystemTypeId": "@yocto",
            "externalId": "yocto/" + config.args.project + "/" + config.args.version,
            "externalIdMetaData": {
                "forge": {
                    "name": "yocto",
                    "separator": ":",
                    "usePreferredNamespaceAlias": True
                },
                "pieces": [
                    config.args.project,
                    config.args.version
                ],
                "prefix": ""
            }
        },
        "relationship": global_values.bdio_proj_rel_list
    }

    bdio = [bdio_header, bdio_project, global_values.bdio_comps_layers, global_values.bdio_comps_recipes]
    if not utils.write_bdio(bdio):
        sys.exit(3)


def process_patched_cves(bd, version, vuln_list):

    try:
        # vulnerable_components_url = hub.get_link(version, "vulnerable-components") + "?limit=9999"
        headers = {'Accept': 'application/vnd.blackducksoftware.bill-of-materials-6+json'}
        # response = hub.execute_get(vulnerable_components_url, custom_headers=custom_headers)
        # vulnerable_bom_components = response.json().get('items', [])
        resp = bd.get_json(version['_meta']['href'] + '/vulnerable-bom-components?limit=5000', headers=headers)

        count = 0

        for comp in resp['items']:
            if comp['vulnerabilityWithRemediation']['source'] == "NVD":
                if comp['vulnerabilityWithRemediation']['vulnerabilityName'] in vuln_list:
                    if utils.patch_vuln(bd, comp):
                        print("		Patched {}".format(comp['vulnerabilityWithRemediation']['vulnerabilityName']))
                        count += 1
            elif comp['vulnerabilityWithRemediation']['source'] == "BDSA":
                vuln_url = "/api/vulnerabilities/" + comp['vulnerabilityWithRemediation'][
                    'vulnerabilityName']
                # custom_headers = {'Accept': 'application/vnd.blackducksoftware.vulnerability-4+json'}
                # resp = hub.execute_get(vuln_url, custom_headers=custom_headers)
                vuln = bd.get_json(vuln_url)
                # vuln = resp.json()
                # print(json.dumps(vuln, indent=4))
                for x in vuln['_meta']['links']:
                    if x['rel'] == 'related-vulnerability':
                        if x['label'] == 'NVD':
                            cve = x['href'].split("/")[-1]
                            if cve in vuln_list:
                                if utils.patch_vuln(bd, comp):
                                    print("		Patched " + vuln['name'] + ": " + cve)
                                    count += 1
                        break

    except Exception as e:
        print("ERROR: Unable to get components from project via API\n" + str(e))
        return False

    print("- {} CVEs marked as patched in project '{}/{}'".format(count, config.args.project, config.args.version))
    return True


def proc_replacefile():
    print("- Processing replacefile {}: ...".format(config.args.replacefile))
    try:
        r = open(config.args.replacefile, "r")
        for line in r:
            # if re.search('^LAYER ', line):
            #     rep_layers[line.split()[1]] = line.split()[2]
            if re.search('^RECIPE ', line):
                origrec = line.split()[1]
                reprec = line.split()[2]
                if len(origrec.split('/')) != 3 or len(reprec.split('/')) != 3:
                    print('Ignored line {} - complete layer/recipe/revision required'.format(line))
                    continue
                global_values.replace_recipes_dict[line.split()[1]] = line.split()[2]
            else:
                print('Ignored line {}'.format(line))
        r.close()
    except Exception as e:
        print("ERROR: Unable to read replacefile file {}\n".format(config.args.replacefile) + str(e))
        return False

    print("	{} replace entries processed".format(len(global_values.replace_recipes_dict)))
    return True
