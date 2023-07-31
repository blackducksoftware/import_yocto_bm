#!/usr/bin/env python

# import argparse
# import json
import logging
import sys
# import os
import requests
import platform
import asyncio

from bd_scan_yocto.bdcomponentlist import ComponentList
from blackduck import Client
from bd_scan_yocto import global_values
from bd_scan_yocto import config
from bd_scan_yocto import bd_asyncdata

script_version = '2.1'


def check_projver(bd, proj, ver):
	params = {
		'q': "name:" + proj,
		'sort': 'name',
	}

	projects = bd.get_resource('projects', params=params)
	for p in projects:
		if p['name'] == proj:
			versions = bd.get_resource('versions', parent=p, params=params)
			for v in versions:
				if v['versionName'] == ver:
					return p, v
			break
	else:
		print("Version '{}' does not exist in project '{}'".format(ver, proj))
		sys.exit(2)

	print("Project '{}' does not exist".format(proj))
	print('Available projects:')
	projects = bd.get_resource('projects')
	for proj in projects:
		print(proj['name'])
	sys.exit(2)


def get_bom_components(bd, verdict):
	comp_dict = {}
	res = bd.list_resources(verdict)

	blocksize = 1000

	projver = res['href']
	thishref = projver + f"/components?limit={blocksize}"
	headers = {
		'accept': "application/vnd.blackducksoftware.bill-of-materials-6+json",
	}
	res = bd.get_json(thishref, headers=headers)
	if 'totalCount' in res and 'items' in res:
		total_comps = res['totalCount']
	else:
		return comp_dict

	downloaded_comps = 0
	while downloaded_comps < total_comps:
		downloaded_comps += len(res['items'])

		bom_comps = res['items']

		for comp in bom_comps:
			if 'componentVersion' not in comp:
				continue
			compver = comp['componentVersion']

			comp_dict[compver] = comp

		thishref = projver + f"/components?limit={blocksize}&offset={downloaded_comps}"
		res = bd.get_json(thishref, headers=headers)
		if 'totalCount' not in res or 'items' not in res:
			break

	return comp_dict


def get_all_projects(bd):
	projs = bd.get_resource('projects', items=True)

	projlist = []
	for proj in projs:
		projlist.append(proj['name'])
	return projlist


def load_bd_project(bdproj, bdver):
	bd = Client(
		token=global_values.bd_api,
		base_url=global_values.bd_url,
		verify=(not global_values.bd_trustcert),  # TLS certificate verification
		timeout=60
	)

	project, version = check_projver(bd, bdproj, bdver)

	bom_components = get_bom_components(bd, version)

	process_bom(bd, bom_components)

	return


def process_bom(bd, bom_components):
	logging.info("Processing {} bom entries ...".format(len(bom_components)))

	# logging.info("Downloading Async data ...")
	# all_copyrights = bd_asyncdata.get_data_async(bd, bom_components, args.blackduck_trust_cert)

	# copyrightprocessor = CopyrightProcessor(args.code_languages.split(','), int(args.max_lines))

	componentlist = ComponentList()
	# componentlist.process_bom(bd, bom_components, all_copyrights, copyrightprocessor, args.notstrict)
	componentlist.process_bom(bd, bom_components)

	all_comp_count = len(bom_components)
	ignored_comps = componentlist.count_ignored_comps()

	print("Processed Black Duck project from BD Server {}".format(global_values.bd_url))
	print(f"Component counts:\n- Total Components {all_comp_count}")
	print(f"- Ignored Components {ignored_comps}")

	return


def process_project(bd, project, version, bearer_token):
    print('Getting components from project ... found ', end='')
    bom_compsdict = get_bom_components(version)
    print("{}".format(str(len(bom_compsdict))))

    print('\nASYNC - Getting component data ... ')

    if platform.system() == "Windows":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    pkgmatch_dict = asyncio.run(bd_asyncdata.async_main(bom_compsdict, bearer_token, version))

    ignore_comps = []
    count_ignored = 0
    ignore_array = []

    for comp in bom_compsdict.keys():
        if not pkgmatch_dict[comp]:
            # Ignore this component
            ignore_array.append(bom_compsdict[comp]['_meta']['href'])
            count_ignored += 1
            if count_ignored >= 99:
                ignore_comps.append(ignore_array)
                ignore_array = []
                count_ignored = 0

    ignore_comps.append(ignore_array)
    for ignore_array in ignore_comps:
        bulk_data = {
            "components": ignore_array,
            # "reviewStatus": "REVIEWED",
            "ignored": True,
            # "usage": "DYNAMICALLY_LINKED",
            # "inAttributionReport": true
        }

        try:
            url = version['_meta']['href'] + '/bulk-adjustment'
            headers = {
                "Accept": "application/vnd.blackducksoftware.bill-of-materials-6+json",
                "Content-Type": "application/vnd.blackducksoftware.bill-of-materials-6+json"
            }
            r = bd.session.patch(url, json=bulk_data, headers=headers)
            r.raise_for_status()
        except requests.HTTPError as err:
            bd.http_error_handler(err)

    return
