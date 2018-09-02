package slackawsapigw

import (
	"encoding/json"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"github.com/masahide/slacksigverify"
)

var (
	jsonBlob = []byte(`{
    "resource": "/",
    "path": "/",
    "httpMethod": "POST",
    "headers": {
        "Accept": "*/*",
        "Accept-Encoding": "gzip,deflate",
        "CloudFront-Forwarded-Proto": "https",
        "CloudFront-Is-Desktop-Viewer": "true",
        "CloudFront-Is-Mobile-Viewer": "false",
        "CloudFront-Is-SmartTV-Viewer": "false",
        "CloudFront-Is-Tablet-Viewer": "false",
        "CloudFront-Viewer-Country": "US",
        "Content-Type": "application/json",
        "Host": "xxxxx.xxx.amazonaws.com",
        "User-Agent": "Slackbot 1.0 (+https://api.slack.com/robots)",
        "Via": "1.1 xxxxxxx.cloudfront.net (CloudFront)",
        "X-Amz-Cf-Id": "xxxxxxxxxxxxxxxxxxx",
        "X-Amzn-Trace-Id": "xxxxxxxxxxxxxxxxxxx",
        "X-Forwarded-For": "1.1.1.1, 1.1.1.1",
        "X-Forwarded-Port": "443",
        "X-Forwarded-Proto": "https",
        "X-Slack-Request-Timestamp": "",
        "X-Slack-Signature": ""
    },
    "queryStringParameters": {
        "hoge": "fuga",
        "uho": "aaa"
    },
    "pathParameters": null,
    "stageVariables": null,
    "requestContext": {
        "accountId": "1111111111",
        "resourceId": "xxxxxxxxxx",
        "stage": "Prod",
        "requestId": "xxxxxxxxxxxxxxxxxxxxxxx",
        "identity": {
            "cognitoIdentityPoolId": "",
            "accountId": "",
            "cognitoIdentityId": "",
            "caller": "",
            "apiKey": "",
            "sourceIp": "1.1.1.1",
            "cognitoAuthenticationType": "",
            "cognitoAuthenticationProvider": "",
            "userArn": "",
            "userAgent": "Slackbot 1.0 (+https://api.slack.com/robots)",
            "user": ""
        },
        "resourcePath": "/",
        "authorizer": null,
        "httpMethod": "POST",
        "apiId": "xxxxxxxxx"
    },
    "body": "{\"token\":\"xxxxxxxxxxxxxxxx\",\"team_id\":\"xxxxxxx\",\"api_app_id\":\"xxxxx\",\"event\":{\"type\":\"channel_created\",\"channel\":{\"id\":\"XXXXXX\",\"is_channel\":true,\"name\":\"test\",\"name_normalized\":\"test\",\"created\":1535696707,\"creator\":\"XXXXXXX\",\"is_shared\":false,\"is_org_shared\":false},\"event_ts\":\"1535696707.000100\"},\"type\":\"event_callback\",\"event_id\":\"XXXXX\",\"event_time\":1535696707,\"authed_users\":[\"XXXXXXX\"]}"
}`)

	kmsResp = kms.GenerateDataKeyOutput{
		CiphertextBlob: []byte{
			0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xcc, 0x53, 0xd5, 0xdb, 0x00, 0xdd, 0x87, 0x90,
			0x00, 0x00, 0x00, 0x00, 0x5d, 0x00, 0x00, 0x00, 0xa5, 0xc2, 0xfd, 0x6a, 0x00, 0xcc, 0x5b, 0x2c,
			0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x30, 0xed, 0x11, 0x04, 0x00, 0x67, 0x59, 0x85,
			0x00, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00, 0x02, 0x3b, 0x01, 0x10, 0x00, 0x2a, 0xc0, 0xe4,
			0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0xed, 0x2f, 0x0b, 0xe7, 0x00, 0x56, 0xa4, 0x04,
			0x00, 0x00, 0x00, 0x00, 0x86, 0x00, 0x00, 0x00, 0x6f, 0x01, 0x30, 0x6d, 0x00, 0x00, 0x30, 0x68,
			0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x01, 0x1e, 0x07, 0x01, 0x00, 0x06, 0x09, 0x60,
			0x00, 0x00, 0x00, 0x00, 0xfc, 0x00, 0x00, 0x00, 0xd0, 0xbf, 0xa9, 0xf3, 0x00, 0x63, 0x1e, 0x8c,
			0x00, 0x00, 0x00, 0x00, 0xfa, 0x00, 0x00, 0x00, 0x00, 0x06, 0x7e, 0x30, 0x00, 0x09, 0x2a, 0x86,
			0x00, 0x00, 0x00, 0x00, 0x8f, 0x00, 0x00, 0x00, 0x2b, 0x13, 0x5f, 0x87, 0x00, 0x02, 0x02, 0x0f,
			0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0x94, 0x06, 0x89, 0x96, 0x00, 0xc5, 0x6e, 0xba,
			0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00,
		}, // 184byte
		KeyId:     aws.String("arn:aws:kms:ap-northeast-1:00000000:key/1111111-1111-1111-111111111"),
		Plaintext: []byte("01234566890123456689012345668901"), // 32byte

	}
	kmsMock = mockedKMS{resp: kmsResp}
)

func TestHandler(t *testing.T) {
	t.Run("Invalid Signature", func(t *testing.T) {
		var request events.APIGatewayProxyRequest
		s := SlackHanlder{KmsSvc: kmsMock}
		res, err := s.Handler(request)
		if err != nil && err.Error() != "Invalid request signature" {
			t.Fatalf("response: %v,res:%v", err, res)
		}
	})

	t.Run("Unknown APIEvnetType", func(t *testing.T) {
		var request events.APIGatewayProxyRequest
		json.Unmarshal(jsonBlob, &request)
		request.Body = `
		{
    "token": "xxxxxxxxxx",
    "team_id": "xxxxxxxxxx",
    "api_app_id": "xxxxxxxxxx",
    "event": {
        "type": "channel_created",
        "channel": {
            "id": "xxxxxxxxxx",
            "is_channel": true,
            "name": "test",
            "name_normalized": "test",
            "created": 1535696707,
            "creator": "xxxxx",
            "is_shared": false,
            "is_org_shared": false
        },
        "event_ts": "1535696707.000100"
    },
    "type": "hoge",
    "event_id": "xxxxx",
    "event_time": 1535696707,
    "authed_users": [
        "xxxxx"
    ]
}`
		slacksigverify.NowUnix = func() int64 { return 1535696707 }
		request.Headers[`X-Slack-Signature`] = "v0=6d0f44afb7e191d4cdd5a243cdedc759f7b7b6351fb8b5daf7fca5ba3b35366a"
		s := SlackHanlder{KmsSvc: kmsMock}
		res, err := s.Handler(request)
		if err != nil && err.Error() != "Unknown APIEvnetType:hoge" {
			t.Fatalf("Error failed to trigger with an invalid HTTP response: %v,res:%v", err, res)
		}
	})
	t.Run("Unable decode IP", func(t *testing.T) {
		s := SlackHanlder{KmsSvc: kmsMock}
		_, err := s.Handler(events.APIGatewayProxyRequest{})
		if err == nil {
			t.Fatal("Error failed to trigger with an invalid HTTP response")
		}
	})

	t.Run("Successful Request", func(t *testing.T) {
		var request events.APIGatewayProxyRequest
		json.Unmarshal(jsonBlob, &request)
		slacksigverify.NowUnix = func() int64 { return 1535696707 }
		request.Headers[`X-Slack-Signature`] = "v0=e6f3cb584a5c44d3ba9c776246e93492d32cdb56aa42bb2eaf168ccd1732f988"
		request.Body = `
		   		{
		       "token": "xxxxxxxxxx",
		       "team_id": "xxxxxxxxxx",
		       "api_app_id": "xxxxxxxxxx",
		       "event": {
		           "type": "channel_created",
		           "channel": {
		               "id": "xxxxxxxxxx",
		               "is_channel": true,
		               "name": "test",
		               "name_normalized": "test",
		               "created": 1535696707,
		               "creator": "xxxxx",
		               "is_shared": false,
		               "is_org_shared": false
		           },
		           "event_ts": "1535696707.000100"
		       },
		       "type": "event_callback",
		       "event_id": "xxxxx",
		       "event_time": 1535696707,
		       "authed_users": [
		           "xxxxx"
		       ]
		   }`
		s := SlackHanlder{KmsSvc: kmsMock}
		_, err := s.Handler(request)
		if err != nil {
			t.Fatalf("err:%s", err)
		}
	})
}

func TestUrlVerify(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		var request RequestData
		request.Body = `{"token":"xxxxxx","challenge":"xxxxxxxxxxx","type":"url_verification"}`
		res, err := urlVerify(request)
		if err != nil {
			t.Fatalf("response: %v,err:%v", res, err)
		}
		if res.Body != `{"Challenge":"xxxxxxxxxxx"}` {
			t.Fatalf("body: %v", res.Body)
		}
	})
	t.Run("Failed Unmarshal", func(t *testing.T) {
		var request RequestData
		request.Body = `"}`
		res, err := urlVerify(request)
		if err == nil {
			t.Fatalf("response: %v,err:%v", res, err)
		}
		if err.Error() != "unexpected end of JSON input" {
			t.Fatalf("response: %v,err:%v", res, err)
		}
	})
}

type mockedKMS struct {
	kmsiface.KMSAPI
	resp kms.GenerateDataKeyOutput
}

func (m mockedKMS) GenerateDataKey(in *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error) {
	// Only need to return mocked response output
	res := m.resp
	res.Plaintext = make([]byte, len(m.resp.Plaintext))
	copy(res.Plaintext, m.resp.Plaintext)
	return &res, nil
}
func (m mockedKMS) Decrypt(in *kms.DecryptInput) (*kms.DecryptOutput, error) {
	// Only need to return mocked response output
	decResp := kms.DecryptOutput{KeyId: m.resp.KeyId, Plaintext: make([]byte, len(m.resp.Plaintext))}
	copy(decResp.Plaintext, m.resp.Plaintext)
	return &decResp, nil
}
