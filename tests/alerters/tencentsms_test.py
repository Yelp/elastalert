import json
import logging
import pytest

from unittest import mock

from requests import RequestException
from requests.auth import HTTPProxyAuth

from elastalert.alerters.tencentsms import TencentSMSAlerter
from elastalert.loaders import FileRulesLoader
from elastalert.util import EAException


def test_tencentsms_template_parm():
    rule = {
        'name': 'Test tencentsms Template Parm',
        'type': 'any',
        'alert': ["tencent_sms"],
        "tencent_sms_secret_id": "secret_id",
        "tencent_sms_secret_key": "secret_key",
        "tencent_sms_sdk_appid": "1400006666",
        "tencent_sms_to_number": [
            "+8613711112222"
        ],
        "tencent_sms_template_id": "1123835",
        "tencent_sms_template_parm": [
            "/kubernetes/pod_name"
        ]  
    }
    
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = TencentSMSAlerter(rule)
    match = [
        {
            "kubernetes": {
                "namespace_name": "nginx",
                "pod_name": "ngin.nginx-6bd96d6f74-2ts4x"
            },
            "time": "2021-09-04T03:13:24.192875Z",
            "message": "2021-09-03T14:34:08+0000|INFO|vector eps : 192.168.0.2:10000,",
        }
    ]
    excepted = ["ngin.nginx-6bd96d6f74-2ts4x"]
    actual = alert.create_template_parm(match)
    assert excepted == actual