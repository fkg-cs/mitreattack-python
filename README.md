# mitreattack-python

This repository contains a set of Python tools and utilities for working with ATT&CK data.
For more information,
see the [full documentation](https://mitreattack-python.readthedocs.io/) on ReadTheDocs.

## Install

To use this package, install the mitreattack-python library with [pip](https://pip.pypa.io/en/stable/):

```shell
pip install mitreattack-python
```

Note: the library requires [python3](https://www.python.org/).

## MitreAttackData Library

The ``MitreAttackData`` library is used to read in and work with MITRE ATT&CK STIX 2.0 content. This library provides 
the ability to query the dataset for objects and their related objects. This is the main content of mitreattack-python;
you can read more about other modules in this library under "Additional Modules".

## fkg-cs directory 

This directory contains all the work done by FKG, wich is a CTI system that operates with the ATT&CK data manipulation in python and the main core of Janus project:

### CLI_py_utils
This directory contains many python file function with CLI that helps to replicare ATT&CK navigator with python objects.
It also contains a base scraper that manages the risk for each technique based on CVSS 3.1 base metrics.

It is very helpful for future development in MitreAttackData Library and serve as a guideline for programmers that need to integrate python data manituplation of MITRE MATRIXES.
### Janus directory 
This directory contains a web system that shows all the data of mitre, data manipulation in python and risk scores in a more accessible way.
The app.py file runs the Flask server to view the page at: http://127.0.0.1:5000
Once you start the server you can use the website on your browser.

### json directory
This directory contains all the json files that the project needs, such as: json_matrix that contins ATT&CK matixes information and json_CVE that contains a year by year archive divided by its identification number.

### CTI

[Cyber Threat Intelligence repository](https://github.com/mitre/cti) of the ATT&CK catalog expressed in STIX 2.0 JSON.
This repository also contains [our USAGE document](https://github.com/mitre/cti/blob/master/USAGE.md) which includes
additional examples of accessing and parsing our dataset in Python.

### ATT&CK

ATT&CK® is a curated knowledge base and model for cyber adversary behavior, reflecting the various phases of
an adversary’s lifecycle, and the platforms they are known to target.
ATT&CK is useful for understanding security risk against known adversary behavior,
for planning security improvements, and verifying defenses work as expected.

<https://attack.mitre.org>

### STIX

Structured Threat Information Expression (STIX<sup>™</sup>) is a language and serialization format used to exchange cyber threat intelligence (CTI).

STIX enables organizations to share CTI with one another in a consistent and machine-readable manner,
allowing security communities to better understand what computer-based attacks they are most likely to
see and to anticipate and/or respond to those attacks faster and more effectively.

STIX is designed to improve many capabilities, such as collaborative threat analysis, automated threat exchange, automated detection and response, and more.

<https://oasis-open.github.io/cti-documentation/>




## Notice

Copyright 2024 The MITRE Corporation

Approved for Public Release; Distribution Unlimited. Case Number 19-0486.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   <http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

This project makes use of ATT&CK®

[ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/)
