import requests
import os
# import subprocess
import sys

from pathlib import Path

from bd_scan_yocto import global_values
# from bd_scan_yocto import utils
# from bd_scan_yocto import config


def get_detect():
    cmd = ''
    if global_values.detect_jar == '':
        tdir = os.path.join(str(Path.home()), "synopsys-detect")
        if not os.path.isdir(tdir):
            os.mkdir(tdir)
        tdir = os.path.join(tdir, "download")
        if not os.path.isdir(tdir):
            os.mkdir(tdir)
        if not os.path.isdir(tdir):
            print("ERROR: Cannot create synopsys-detect folder in $HOME")
            sys.exit(2)
        shpath = os.path.join(tdir, 'detect8.sh')

        j = requests.get("https://detect.synopsys.com/detect8.sh")
        if j.ok:
            open(shpath, 'wb').write(j.content)
            if not os.path.isfile(shpath):
                print("ERROR: Cannot download Synopsys Detect shell script "
                      " download manually and use --detect-jar-path option")
                sys.exit(2)

            cmd = "/bin/bash " + shpath
    else:
        cmd = "java " + global_values.detect_jar

    return cmd


def run_detect_sigscan(tdir, proj, ver, trust):

    cmd = get_detect()

    detect_cmd = cmd
    detect_cmd += f"--detect.source.path={tdir} --detect.project.name={proj} " + \
                  f"--detect.project.version.name={ver} "
    detect_cmd += f"--blackduck.url={global_values.bd_url} "
    detect_cmd += f"--blackduck.api.token={global_values.bd_api} "
    if trust:
        detect_cmd += "--blackduck.trust.cert=true "
    detect_cmd += "--detect.wait.for.results=true "

    print("\nRunning Detect on identified packages ...")
    # output = subprocess.check_output(detect_cmd, stderr=subprocess.STDOUT)
    # mystr = output.decode("utf-8").strip()
    # lines = mystr.splitlines()
    os.system(detect_cmd)


def run_detect_for_bitbake():
    cmd = get_detect()

    detect_cmd = cmd
    detect_cmd += f"--detect.project.name={global_values.bd_project} " + \
                  f"--detect.project.version.name={global_values.bd_version} "
    detect_cmd += f"--blackduck.url={global_values.bd_url} "
    detect_cmd += f"--blackduck.api.token={global_values.bd_api} "
    if global_values.bd_trustcert:
        detect_cmd += "--blackduck.trust.cert=true "
    detect_cmd += "--detect.wait.for.results=true "
    detect_cmd += f"--detect.bitbake.package.names={global_values.target} "
    detect_cmd += "--detect.tools=DETECTOR "
    detect_cmd += f"--detect.bitbake.package.names={global_values.target} "
    detect_cmd += "--detect.bitbake.dependency.types.excluded=BUILD "

    print("\nRunning Detect on Bitbake project ...")
    # output = subprocess.check_output(detect_cmd, stderr=subprocess.STDOUT)
    # mystr = output.decode("utf-8").strip()
    # lines = mystr.splitlines()
    os.system(detect_cmd)
