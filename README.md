# What is IREC?
A cross platform framework to recover driver's communication interface. It aims to recover communication interface for fuzzing a kernel driver.

IREC was implemented using angr and radare2, and generates json files to perform effective fuzzing. That is, it can extract the interface information and constraints of the wdm driver very easily and quickly without any further inefficient manual work. 

### Components of IREC

```shell
IREC
├── test-drivers                            # Test drivers to verify that madcore is working.
├── projects                                # Driver analysis projects
│   ├── symbolic                            # Techniques using symbolic execution.
│   ├── static                              # Techniques using static analysis techniques
│   └──wdm.py                               # WDM driver analysis framework
└── irec.py                                 # Main module
└── angPT.py                                # angPT module
```

## Getting started

We recommend python3.8 virtual environment to use IREC.

```shell
# make virtual environment
$ pip install virtualenvwrapper
$ sudo apt install python3-virtualenv

$ virtualenv $YOUR_NAME
$ source $YOUR_NAME/bin/activate

# requirements
$ apt install radare2
$ pip install angr boltons argparse ipdb r2pipe angr-utils
```
