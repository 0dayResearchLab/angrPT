import json
import os
import pytest

# Directory and file path for the generated JSON
RESULT_DIR = os.path.join(os.path.dirname(__file__), os.pardir, 'result', 'wdm')
JSON_PATH = os.path.join(RESULT_DIR, 'wdm.json')

# Expected IOCTL interface output
EXPECTED = [
    {'IoControlCode': '0x222000', 'InBufferLength': ['4-inf'],  'OutBufferLength': ['0-inf']},
    {'IoControlCode': '0x222004', 'InBufferLength': ['0-inf'],  'OutBufferLength': ['16-16']},
    {'IoControlCode': '0x222008', 'InBufferLength': ['8-8'],   'OutBufferLength': ['8-8']},
    {'IoControlCode': '0x22200c', 'InBufferLength': ['32-inf'], 'OutBufferLength': ['32-inf']},
    {'IoControlCode': '0x222010', 'InBufferLength': ['1-1'],   'OutBufferLength': ['0-inf']},
    {'IoControlCode': '0x222014', 'InBufferLength': ['2-inf'],  'OutBufferLength': ['0-inf']},
    {'IoControlCode': '0x222018', 'InBufferLength': ['0-inf'],  'OutBufferLength': ['49-inf']},
    {'IoControlCode': '0x22201c', 'InBufferLength': ['16-16'], 'OutBufferLength': ['64-64']},
    {'IoControlCode': '0x222020', 'InBufferLength': ['4-inf'],  'OutBufferLength': ['0-inf']},
    {'IoControlCode': '0x222024', 'InBufferLength': ['0-inf'],  'OutBufferLength': ['0-inf']},
    {'IoControlCode': '0x222028', 'InBufferLength': ['2-inf'],  'OutBufferLength': ['0-inf']},
]

def test_json_file_exists():
    assert os.path.isfile(JSON_PATH), f"JSON file not found: {JSON_PATH}"

def test_json_matches_expected():
    with open(JSON_PATH, 'r') as f:
        data = json.load(f)
    assert data == EXPECTED, "IOCTL interface output does not match expected"
