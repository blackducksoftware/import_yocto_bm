import argparse
import os
import sys
import json

parser = argparse.ArgumentParser(description='Process KB csv', prog='import_yocto_bm')

# parser.add_argument("projfolder", nargs="?", help="Yocto project folder to analyse", default=".")
parser.add_argument("kbcsv", type=str, help='csv file')

args = parser.parse_args()

if not os.path.isfile(args.kbcsv):
    print('CSV file {} does not exist'.format(args.kbcsv))
    sys.exit(1)

entry_list = []
recipe_dict = {}

try:
    c = open(args.kbcsv, "r")
    for cline in c:
        entry = cline.strip().replace('"', '')
        carr = entry.split('/')
        if len(carr) > 2:
            layer = carr[0]
            recipe = carr[1]
            version = carr[2]
            if len(version) > 0:
                entry_list.append(entry)
                if recipe in recipe_dict:
                    recipe_dict[recipe].append(f'{layer}/{version}')
                else:
                    recipe_dict[recipe] = [f'{layer}/{version}']
    c.close()

    with open('../kb_recipes.json', "w") as f:
        f.write(json.dumps(recipe_dict, indent=4))
    with open('../kb_entries.json', "w") as f:
        f.write(json.dumps(entry_list, indent=4))

except Exception as e:
    print("ERROR: Unable to process csv file {}\n".format(args.kbcsv) + str(e))
