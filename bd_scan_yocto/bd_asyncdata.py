import aiohttp
import asyncio
# import platform
# import logging

from bd_scan_yocto import global_values


async def async_main(comps, token, ver):
    async with aiohttp.ClientSession(trust_env=True) as session:
        data_tasks = []
        # comment_tasks = []
        file_tasks = []
        # lic_tasks = []
        # url_tasks = []
        # supplier_tasks = []
        # child_tasks = []
        count = 0
        for url, comp in comps.items():
            count += 1

            file_task = asyncio.ensure_future(async_get_files(session, comp, token))
            file_tasks.append(file_task)

        await asyncio.gather(*data_tasks)
        all_files = dict(await asyncio.gather(*file_tasks))

        await asyncio.sleep(0.250)
        print(f'Got {count} component data elements')

        print(all_files)

    return all_files


async def async_get_data(session, compurl, token):
    if global_values.bd_trustcert:
        ssl = False
    else:
        ssl = None

    thishref = compurl + '/origins?limit=1000'
    headers = {
        'accept': "application/vnd.blackducksoftware.bill-of-materials-6+json",
        'Authorization': f'Bearer {token}',
    }
    # resp = globals.bd.get_json(thishref, headers=headers)
    async with session.get(thishref, headers=headers, ssl=ssl) as resp:
        result_data = await resp.json()
    return 1


async def async_get_files(session, comp, token):
    if not global_values.bd_trustcert:
        ssl = False
    else:
        ssl = None

    retfile = "NOASSERTION"
    hrefs = comp['_meta']['links']

    link = next((item for item in hrefs if item["rel"] == "matched-files"), None)
    if link:
        thishref = link['href'] + '?limit=1000'
        headers = {
            'Authorization': f'Bearer {token}',
            'accept': "application/vnd.blackducksoftware.bill-of-materials-6+json",
        }

        archive = False
        async with session.get(thishref, headers=headers, ssl=ssl) as resp:
            result_data = await resp.json()
            # cfile = result_data['items']
            # if len(cfile) > 0:
            #     rfile = cfile[0]['filePath']['path']
            #     for ext in ['.jar', '.ear', '.war', '.zip', '.gz', '.tar', '.xz', '.lz', '.bz2', '.7z',
            #                 '.rar', '.rar', '.cpio', '.Z', '.lz4', '.lha', '.arj', '.rpm', '.deb', '.dmg',
            #                 '.gz', '.whl']:
            #         if rfile.endswith(ext):
            #             retfile = rfile
            for item in result_data['items']:
                # if item['filePath']['path'] == item['filePath']['fileName']:
                if item['filePath']['compositePathContext'] == item['filePath']['path'] + '#':
                    print(item['filePath']['path'])
                    archive = True
                    break

    return comp['componentVersion'], archive


