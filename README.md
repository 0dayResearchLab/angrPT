

# What is angrpt?
**AngrPT** recover the Windows Driver's DeviceIoControl Interface. It can provide the Constraint of IoControlCode for get higher coverage in Fuzzing Process.

**AngrPT** also analyze global variable dependencies between iocontrol codes.

It based on [IREC](https://github.com/kirasys/irec) and improve the IREC's limitations.

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

## Install Dependencies

```shell
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