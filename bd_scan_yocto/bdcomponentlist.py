# from blackduck.HubRestApi import HubInstance
import logging
# from copyrightmanager import CopyrightManager


class ComponentList:
    # components_dict = {}

    def __init__(self):
        self.components_dict = {}
        self.ignored_components = {}

    def add(self, compname, copyrightmgr):
        self.components_dict[compname] = copyrightmgr

    def add_ignored(self, compname):
        self.ignored_components[compname] = 1

    def count_comps(self):
        return len(self.components_dict)

    def count_ignored_comps(self):
        return len(self.ignored_components)

    # def count_active_copyrights(self):
    #     count = 0
    #     for compname, copyrightmgr in self.components_dict.items():
    #         count += copyrightmgr.count_active_copyrights()
    #     return count
    #
    # def count_inactive_copyrights(self):
    #     count = 0
    #     for compname, copyrightmgr in self.components_dict.items():
    #         count += copyrightmgr.count_inactive_copyrights()
    #     return count
    #
    # def count_final_copyrights(self):
    #     count = 0
    #     for compname, copyrightmgr in self.components_dict.items():
    #         count += copyrightmgr.count_final_copyrights()
    #     return count

    # def process_bom(self, bd, bom_components, all_copyrights, cprocessor, notstrict):
    def process_bom(self, bd, bom_components):
        logging.info("Processing BOM components ...")
        for compurl, bom_component in bom_components.items():

            if 'componentVersionName' in bom_component:
                bom_component_name = f"{bom_component['componentName']}:{bom_component['componentVersionName']}"
            else:
                bom_component_name = f"{bom_component['componentName']}"
                logging.warning(f"Component found with no version: {bom_component_name}")
                continue

            if bom_component['ignored']:
                logging.info(f"Skipping Ignored Component: {bom_component_name}")
                self.add_ignored(bom_component_name)
                continue
            else:
                logging.info(f"Processing Component: {bom_component_name}")

            if bom_component_name in self.components_dict.keys():
                logging.warning(f"Skipping {bom_component_name} : Already processed")
                continue

            # copyrightmanager = None
            # if 'origins' in bom_component:
            #     for origin in bom_component['origins']:
            #         #
            #         # Find copyright for origin in all_copyrights dict
            #         origcopyrights = []
            #         if origin['origin'] in all_copyrights:
            #             origcopyrights = all_copyrights[origin['origin']]
            #         if len(origcopyrights) > 0:
            #             if copyrightmanager is None:
            #                 copyrightmanager = CopyrightManager(bd, bom_component_name, origcopyrights, notstrict)
            #             else:
            #                 copyrightmanager.add_copyrights(origcopyrights)

            # copyright_list = []
            # rejected_copyrights = []
            # if copyrightmanager is not None:
            #     copyrightmanager.process_copyrights(cprocessor)
            #     self.add(bom_component_name, copyrightmanager)

        return

    # def generate_text_report(self, project, version, showall=False):
    #     output_string = "\n" + project + " " + version + "\n================================\n"
    #     for compname, copyrightmgr in self.components_dict.items():
    #         output_string += '\n' + copyrightmgr.output_copyrights_text(showall)
    #         # if args.show_rejected:
    #         #     for copyright in copyrights[component][origin]['rejected']:
    #         #         output_string = output_string + "  REJECTED: " + copyright + "\n"
    #
    #     return output_string
    #
    # def generate_html_report(self, project, version, showall=False):
    #     output = f"""
    #         <!doctype html>
    #         <html lang="en">
    #         <head>
    #           <meta charset="utf-8">
    #           <title>Copyright Report</title>
    #           <meta name="description" content="Copyright Report">
    #           <meta name="author" content="BlackDuck">
    #         </head>
    #         <body>
    #         <h1>Project: {project} Version: {version}<h1>
    #         """
    #
    #     for compname, copyrightmgr in self.components_dict.items():
    #         output += copyrightmgr.output_copyrights_html(showall)
    #
    #     output = output + """
    #     </body>
    #     </html>
    #     """
    #     return output
