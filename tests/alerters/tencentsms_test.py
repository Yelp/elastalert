import logging
import pytest
from elastalert.alerters.tencentsms import TencentSMSAlerter
from elastalert.loaders import FileRulesLoader
from elastalert.util import EAException


def test_tencentsms_alert(caplog):
    caplog.set_level(logging.DEBUG)
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

    match = {
        "kubernetes": {
            "namespace_name": "nginx",
            "pod_name": "ngin.nginx-6bd96d6f74-2ts4x"
        },
        '@timestamp': '2014-01-01T00:00:00',
        "message": "2021-09-03T14:34:08+0000|INFO|vector eps : 192.168.0.2:10000,",
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)

    with pytest.raises(EAException) as ea:
        alert = TencentSMSAlerter(rule)
        alert.alert([match])
    assert 'The SecretId is not found' in str(ea)


def test_tencentsms_get_info():
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
        "tencent_sms_template_id": "1123835"
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = TencentSMSAlerter(rule)

    excepted = {
        'type': 'tencent sms',
        'to_number': ["+8613711112222"]
    }
    actual = alert.get_info()
    assert excepted == actual


@pytest.mark.parametrize('tencent_sms_template_parm, expected_data', [
    ([], []),
    (['/kubernetes/pod_name'], ["ngin.nginx-6bd96d6f74-2ts4x"]),
])
def test_tencentsms_template_parm(tencent_sms_template_parm, expected_data):
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
        "tencent_sms_template_parm": tencent_sms_template_parm
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
    actual = alert.create_template_parm(match)
    assert expected_data == actual


@pytest.mark.parametrize('key, val, expected_data', [
    (
        'tencent_sms_secret_id',
        '',
        'Missing required option(s): tencent_sms_secret_id'
    ),
    (
        'tencent_sms_secret_key',
        '',
        'Missing required option(s): tencent_sms_secret_key'
    ),
    (
        'tencent_sms_template_id',
        '',
        'Missing required option(s): tencent_sms_template_id'
    ),
    (
        'tencent_sms_sdk_appid',
        '',
        'Missing required option(s): tencent_sms_sdk_appid'
    ),
])
def test_tencentsms_required_error(key, val, expected_data):
    try:
        rule = {
            'name': 'Test tencentsms Rule',
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
        rule[key] = val
        print(rule)

        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = TencentSMSAlerter(rule)

        actual_data = alert.get_info()
        assert expected_data == actual_data
    except Exception as ea:
        assert expected_data in str(ea)
