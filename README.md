# What is angrpt?
A cross platform framework to recover driver's communication interface. It aims to recover communication interface for fuzzing a kernel driver.

angrpt was implemented using angr and radare2, and generates json files to perform effective fuzzing. That is, it can extract the interface information and constraints of the wdm driver very easily and quickly without any further inefficient manual work. 

### Components of angrPT

```shell
angrPT
├── test-drivers                            # Test drivers to verify that madcore is working.
├── projects                                # Driver analysis projects
│   ├── symbolic                            # Techniques using symbolic execution.
│   ├── static                              # Techniques using static analysis techniques
│   └──wdm.py                               # WDM driver analysis 
angrPT Module
│   └──mangrpt.py                           # angrpt tech module
framework
└── angrpt.py                               # Main module
```

## Getting started

We recommend python3.8 virtual environment to use angrpt.

```shell
# make virtual environment
pip uninstall virtualenv
pip install virtualenv
sudo apt install python3-virtualenv -y

virtualenv $YOUR_NAME
source $YOUR_NAME/bin/activate

pip install angr
pip install virtualenvwrapper
pip install angr boltons argparse ipdb r2pipe angr-utils

git clone https://github.com/angr/angr-dev.git
cd angr-dev
git clone https://github.com/axt/bingraphvis
pip install -e ./bingraphvis
git clone https://github.com/axt/angr-utils
pip install -e ./angr-utils
```

## Starting Analyze 
```
python3 angrpt.py -d [Driver Name] --user-static [Address of Device IoControl Handler]
```