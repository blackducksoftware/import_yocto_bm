import setuptools
import platform
from bd_scan_yocto import global_values

platform_system = platform.system()

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="bd_scan_yocto",
    version=f"{global_values.version}",
    author="Matthew Brady",
    author_email="w3matt@gmail.com",
    description="Process a built Yocto project to create a Black Duck project version",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/blackducksoftware/import_yocto_bm",
    packages=setuptools.find_packages(),
    install_requires=['blackduck>=1.0.4',
                      'requests',
                      ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.0',
    entry_points={
        'console_scripts': ['bd_scan_yocto=bd_scan_yocto.main:main'],
    },
)
