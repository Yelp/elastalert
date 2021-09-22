from elastalert.alerts import Alerter, BasicMatchString
from elastalert.util import EAException, elastalert_logger
import json
from tencentcloud.common import credential
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.sms.v20210111 import models
from tencentcloud.sms.v20210111.sms_client import SmsClient 
from jsonpointer import resolve_pointer


class TencentSMSAlerter(Alerter):
    # en doc: https://intl.cloud.tencent.com/document/product/382/40606
    # zh-cn doc: https://cloud.tencent.com/document/product/382/43196
    """ Send alert using tencent SMS service """

    # By setting required_options to a set of strings
    # You can ensure that the rule config file specifies all
    # of the options. Otherwise, ElastAlert 2 will throw an exception
    # when trying to load the rule.
    required_options = frozenset([
        'tencent_sms_secret_id',
        'tencent_sms_secret_key',
        'tencent_sms_sdk_appid',
        'tencent_sms_to_number',
        'tencent_sms_template_id',
    ])

    def __init__(self, *args):
        super(TencentSMSAlerter, self).__init__(*args)
        self.tencent_sms_secret_id = self.rule.get('tencent_sms_secret_id')
        self.tencent_sms_secret_key = self.rule.get('tencent_sms_secret_key')
        self.tencent_sms_sdk_appid = self.rule.get('tencent_sms_sdk_appid')
        self.tencent_sms_to_number = self.rule.get('tencent_sms_to_number', [])
        self.tencent_sms_region = self.rule.get('tencent_sms_region', 'ap-guangzhou')
        self.tencent_sms_sign_name = self.rule.get('tencent_sms_sign_name')  # this parameter is required for Mainland China SMS.
        self.tencent_sms_template_id = self.rule.get('tencent_sms_template_id')
        self.tencent_sms_template_parm = self.rule.get('tencent_sms_template_parm', [])

    # Alert is called
    def alert(self, matches):
        try:
            elastalert_logger.debug("matches:%s", json.dumps(matches))
            client = self.get_client()
            # Instantiate a request object. You can further set the request parameters according to the API called and actual conditions
            # You can directly check the SDK source code to determine which attributes of `SendSmsRequest` can be set
            # An attribute may be of a basic type or import another data structure
            # We recommend you use the IDE for development where you can easily redirect to and view the documentation of each API and data structure
            req = models.SendSmsRequest()
            # Settings of a basic parameter:
            # The SDK uses the pointer style to specify parameters, so even for basic parameters, you need to use pointers to assign values to them.
            # The SDK provides encapsulation functions for importing the pointers of basic parameters
            # Help link:
            # SMS console: https://console.cloud.tencent.com/smsv2
            # sms helper: https://intl.cloud.tencent.com/document/product/382/3773?from_cn_redirect=1
            # SMS application ID, which is the `SdkAppId` generated after an application is added in the [SMS console], such as 1400006666
            # 短信应用ID: 短信SdkAppid在 [短信控制台] 添加应用后生成的实际SdkAppid，示例如 1400006666
            req.SmsSdkAppId = self.tencent_sms_sdk_appid

            # SMS signature content, which should be encoded in UTF-8. You must enter an approved signature, which can be viewed in the [SMS console]
            # 短信签名内容: 使用 UTF-8 编码，必须填写已审核通过的签名，签名信息可登录 [短信控制台] 查看
            req.SignName = self.tencent_sms_sign_name

            # SMS code number extension, which is not activated by default. If you need to activate it, please contact [SMS Helper]
            # 短信码号扩展号: 默认未开通，如需开通请联系 [sms helper]
            req.ExtendCode = ""

            # User session content, which can carry context information such as user-side ID and will be returned as-is by the server
            # 用户的 session 内容: 可以携带用户侧 ID 等上下文信息，server 会原样返回
            # req.SessionContext = "xxx"

            # `senderid` for Global SMS, which is not activated by default. If you need to activate it, please contact [SMS Helper] for assistance. This parameter should be left empty for Mainland China SMS
            # 国际/港澳台短信 senderid: 国内短信填空，默认未开通，如需开通请联系 [sms helper]
            # req.SenderId = ""

            # Target mobile number in the E.164 standard (+[country/region code][mobile number])
            # Example: +8613711112222, which has a + sign followed by 86 (country/region code) and then by 13711112222 (mobile number). Up to 200 mobile numbers are supported
            # 下发手机号码，采用 e.164 标准，+[国家或地区码][手机号]
            # 示例如：+8613711112222,其中前面有一个+号 ，86为国家码，13711112222为手机号，最多不要超过200个手机号
            req.PhoneNumberSet = self.tencent_sms_to_number

            # Template ID. You must enter the ID of an approved template, which can be viewed in the [SMS console]
            # 模板 ID: 必须填写已审核通过的模板 ID。模板ID可登录 [短信控制台] 查看
            req.TemplateId = self.tencent_sms_template_id

            # Template parameters. If there are no template parameters, leave it empty
            req.TemplateParamSet = self.create_template_parm(matches)

            elastalert_logger.debug("SendSms request :%s", json.dumps(req.__dict__))

            # Initialize the request by calling the `DescribeInstances` method on the client object. Note: the request method name corresponds to the request object
            # The returned `resp` is an instance of the `DescribeInstancesResponse` class which corresponds to the request object
            resp = client.SendSms(req)
            # A string return packet in JSON format is outputted
            elastalert_logger.debug("SendSms response :%s", resp.to_json_string())
            for item in resp.SendStatusSet:
                if item.Code != "Ok":
                    raise TencentCloudSDKException(item.Code, item.Message, resp.RequestId)
        except TencentCloudSDKException as e:
            raise EAException("Error posting to TencentSMS: %s" % e)
        elastalert_logger.info("Alert sent to TencentSMS")

    def get_client(self):
        # Required steps:
        # Instantiate an authentication object. The Tencent Cloud account key pair `secretId` and `secretKey` need to be passed in as the input parameters.
        # The example here uses the way to read from the environment variable, so you need to set these two values in the environment variable first.
        # You can also write the key pair directly into the code, but be careful not to copy, upload, or share the code to others;
        # otherwise, the key pair may be leaked, causing damage to your properties.
        # Query the CAM key: https://console.cloud.tencent.com/cam/capi
        cred = credential.Credential(self.tencent_sms_secret_id, self.tencent_sms_secret_key)
        # cred = credential.Credential(
        #     os.environ.get(""),
        #     os.environ.get("")
        # )
        # (Optional) Instantiate an HTTP option
        httpProfile = HttpProfile()
        # If you need to specify the proxy for API access, you can initialize HttpProfile as follows
        # httpProfile = HttpProfile(proxy="http://username:password@proxy IP:proxy port")
        httpProfile.reqMethod = "POST"  # POST request (POST request by default)
        httpProfile.reqTimeout = 30    # Request timeout period in seconds (60 seconds by default)
        httpProfile.endpoint = "sms.tencentcloudapi.com"  # Specify the access region domain name (nearby access by default)
        # Optional steps:
        # Instantiate a client configuration object. You can specify the timeout period and other configuration items
        clientProfile = ClientProfile()
        clientProfile.signMethod = "TC3-HMAC-SHA256"  # Specify the signature algorithm
        clientProfile.language = "en-US"
        clientProfile.httpProfile = httpProfile
        # Instantiate the client object of the requested product (with SMS as an example)
        # The second parameter is the region information. You can directly enter the string `ap-guangzhou` or import the preset constant
        client = SmsClient(cred, self.tencent_sms_region, clientProfile)
        return client

    def create_template_parm(self, matches):
        esData = matches[0]
        templateParam = []
        if len(self.tencent_sms_template_parm) == 0:
            return []
        for key in self.tencent_sms_template_parm:
            templateParam.append(resolve_pointer(esData, key))
        return templateParam

    # get_info is called after an alert is sent to get data that is written back
    # to Elasticsearch in the field "alert_info"
    # It should return a dict of information relevant to what the alert does
    def get_info(self):
        return {
            'type': 'tencent sms',
            'to_number': self.tencent_sms_to_number
        }
