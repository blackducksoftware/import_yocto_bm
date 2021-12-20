import os
import json
import sys
import time
import requests

from import_yocto_bm import global_values
from import_yocto_bm import config


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
    return None, None


def write_bdio(bdio):
    if config.args.output_json != "":
        try:
            o = open(config.args.output_json, "w")
            o.write(json.dumps(bdio, indent=4))
            o.close()
            print("\nJSON project file written to {} - must be manually uploaded".format(config.args.output_json))
        except Exception as e:
            print("ERROR: Unable to write output JSON file {}\n".format(config.args.output_json) + str(e))
            return False

    else:
        import tempfile
        try:
            with tempfile.NamedTemporaryFile(suffix=".jsonld", delete=False) as o:
                config.args.output_json = o.name
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


def patch_vuln(bd, comp):
    status = "PATCHED"
    comment = "Patched by bitbake recipe"

    try:
        # vuln_name = comp['vulnerabilityWithRemediation']['vulnerabilityName']

        comp['remediationStatus'] = status
        comp['remediationComment'] = comment
        # result = hub.execute_put(comp['_meta']['href'], data=comp)
        href = comp['_meta']['href']
        # href = '/'.join(href.split('/')[3:])
        r = bd.session.put(href, json=comp)
        r.raise_for_status()
        if r.status_code != 202:
            return False

    except Exception as e:
        print("ERROR: Unable to update vulnerabilities via API\n" + str(e))
        return False

    return True


def wait_for_bom_completion(bd, ver):
    # Check job status
    try:
        links = ver['_meta']['links']
        link = next((item for item in links if item["rel"] == "bom-status"), None)

        href = link['href']
        # headers = {'Accept': 'application/vnd.blackducksoftware.internal-1+json'}
        # resp = hub.execute_get(href, custom_headers=custom_headers)
        loop = 0
        uptodate = False
        while not uptodate and loop < 80:
            # resp = hub.execute_get(href, custom_headers=custom_headers)
            resp = bd.get_json(href)
            if 'status' in resp:
                uptodate = (resp['status'] == 'UP_TO_DATE')
            elif 'upToDate' in resp:
                uptodate = resp['upToDate']
            else:
                print('ERROR: Unable to determine bom status')
                return False
            if not uptodate:
                time.sleep(15)
            loop += 1

    except Exception as e:
        print("ERROR: {}".format(str(e)))
        return False

    return uptodate


def wait_for_scans_old(bd, ver):
    links = ver['_meta']['links']
    link = next((item for item in links if item["rel"] == "codelocations"), None)

    href = link['href']

    time.sleep(10)
    wait = True
    loop = 0
    while wait and loop < 20:
        # custom_headers = {'Accept': 'application/vnd.blackducksoftware.internal-1+json'}
        # resp = bd.execute_get(href, custom_headers=custom_headers)
        resp = bd.get_json(href)
        for cl in resp['items']:
            print(cl)
            if 'status' in cl:
                status_list = cl['status']
                for status in status_list:
                    if status['operationNameCode'] == "ServerScanning":
                        if status['status'] == "COMPLETED":
                            wait = False
        if wait:
            # time.sleep(15)
            loop += 1

    return not wait


# def wait_for_scans(bd, ver):
#
#     # try:
#     #     resp = bd.get_json('/api/current-user')
#     #
#     #     user_url = resp['_meta']['href']
#     #     notification_url = f'{user_url}/notifications?filter=notificationType%3A\
#     #     VERSION_BOM_CODE_LOCATION_BOM_COMPUTED&limit=100&offset=0'
#     # resp = bd.get_json
#     # time.sleep(10)
#     wait = True
#     loop = 0
#     while wait and loop < 20:
#
#         if wait:
#             # time.sleep(15)
#             loop += 1
#
#     return not wait
#
#
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
    kbrecipes, kbentries = get_kbrecipelist(kbrecdir)

    keys = ['OK', 'REPLACED', 'REPLACED_NOREVISION', 'REPLACED_NOLAYER+REVISION', 'NOTREPLACED_NOVERSION',
            'NOTREPLACED_NOLAYER+VERSION', 'MISSING', 'SKIPPED']
    report = {}
    for key in keys:
        report[key] = []

    layer = ''
    comp = ''
    for recipe in global_values.recipes_dict.keys():
        # print(recipe + "/" + recipes[recipe])
        ver = global_values.recipes_dict[recipe]

        if recipe in global_values.recipe_layer_dict.keys():
            origlayer = global_values.recipe_layer_dict[recipe]
            layer = origlayer
            comp = origlayer + "/" + recipe + "/" + global_values.recipes_dict[recipe]
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

            if comp in global_values.replace_recipes_dict.keys():
                comp = global_values.replace_recipes_dict[comp]

            if comp in kbentries:
                # Component exists in KB
                report['OK'].append(comp)
                print('	- OK       - Component {}/{}: Mapped directly'.format(
                    recipe, global_values.recipes_dict[recipe]))
                continue
        else:
            print('	- SKIPPED  - Component {}/{}: Recipe missing from bitbake-layers output'.format(
                recipe, global_values.recipes_dict[recipe]))
            report['SKIPPED'].append(f"Component {comp}: Recipe missing from bitbake-layers output")
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
                    global_values.recipe_layer_dict[recipe] = arr[0]
                    report['REPLACED'].append(
                        "ORIG={} REPLACEMENT={}/{}/{}: Recipe and version exist in KB, but not within the layer".format(
                            origcomp, arr[0], recipe, ver))
                    break
                elif layer == arr[0] and ver_norev == arr[1]:
                    # Layer, Recipe and version without rev exist in KB
                    print("	- REPLACED - Component {}: Layer, Recipe and version w/o revision in KB - replaced \
with '{}/{}/{}' from KB".format(comp, arr[0], recipe, ver_norev))
                    global_values.recipe_layer_dict[recipe] = arr[0]
                    global_values.recipes_dict[recipe] = ver_norev
                    report['REPLACED'].append(
                        "ORIG={} REPLACEMENT={}/{}/{}: Layer, Recipe and version w/o revision in KB".format(
                            origcomp, arr[0], recipe, ver_norev))
                    break
                elif layer != arr[0] and ver_norev == arr[1]:
                    # Recipe and version without rev exist in KB - layer is different
                    print("	- REPLACED - Component {}: Recipe and version exist in KB, but not within the layer '{}' - \
replaced with '{}/{}/{}' from KB".format(origcomp, layer, arr[0], recipe, ver_norev))
                    global_values.recipe_layer_dict[recipe] = arr[0]
                    global_values.recipes_dict[recipe] = ver_norev
                    report['REPLACED'].append(
                        "ORIG={} REPLACEMENT={}/{}/{}: Recipe and version exist in KB, but not within the layer".format(
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
revision does not - replaced with '{}/{}/{}' from KB".format(origcomp, kbreclayers[kbrecvers.index(kbver)], recipe,
                                                             kbver))
                                    global_values.recipes_dict[recipe] = kbver
                                    report['REPLACED_NOREVISION'].append("ORIG={} REPLACEMENT={}/{}/{}: Layer, \
recipe and version exist in KB, but revision does not".format(
                                        origcomp, kbreclayers[kbrecvers.index(kbver)], recipe, kbver))
                                else:
                                    print("	- REPLACED - Component {}: Recipe and version exist in KB, but revision \
and layer do not - replaced with '{}/{}/{}' from KB".format(comp, kbreclayers[kbrecvers.index(kbver)], recipe, kbver))
                                    global_values.recipe_layer_dict[recipe] = kbreclayers[kbrecvers.index(kbver)]
                                    global_values.recipes_dict[recipe] = kbver
                                    report['REPLACED_NOLAYER+REVISION'].append("ORIG={} REPLACEMENT={}/{}/{}: Recipe \
and version exist in KB, but revision and layer do not".format(
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
        report['MISSING'].append(f"Component {origcomp}: missing from KB")

    print("	Processed {} recipes from Yocto project ({} mapped, {} not mapped, {} skipped) ...".format(
        len(global_values.recipes_dict),
        len(report['OK']) + len(report['REPLACED']) + len(report['REPLACED_NOREVISION']) +
        len(report['REPLACED_NOLAYER+REVISION']),
        len(report['NOTREPLACED_NOVERSION']) + len(report['NOTREPLACED_NOLAYER+VERSION']) + len(report['MISSING']),
        len(report['SKIPPED']))
    )
    if config.args.report != '':
        try:
            repfile = open(config.args.report, "w")
            for key in keys:
                for rep in report[key]:
                    repfile.write(key + ':' + rep + '\n')
        except Exception as e:
            return
        finally:
            repfile.close()
            print(' Report file {} written containing list of mapped layers/recipes.'.format(config.args.report))

    return
