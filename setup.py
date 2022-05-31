#!/usr/bin/env python

"""The setup script."""

from setuptools import setup, find_packages

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = ['Click>=8.1.3', "grpcio>=1.44.0", "pydantic>=1.9.0", "aiofiles>=0.8.0", "pytz>=2022.1"]

test_requirements = [ ]

setup(
    author="Codenotary",
    python_requires='>=3.6',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    description="Community Attestation pip integration",
    entry_points={
        'console_scripts': [
            'cas_pip=cas_pip.cli:main',
        ],
    },
    install_requires=requirements,
    license="Apache Software License 2.0",
    long_description=readme + '\n\n' + history,
    include_package_data=True,
    keywords='cas_pip',
    name='cas_pip',
    packages=find_packages(include=['cas_pip', 'cas_pip.*']),
    test_suite='tests',
    tests_require=test_requirements,
    url='https://github.com/Razikus/cas_pip',
    version='0.1.0',
    zip_safe=False,
)
