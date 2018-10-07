package slackawsapigw

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"github.com/masahide/slacksigverify"
	"github.com/nlopes/slack"
	"github.com/nlopes/slack/slackevents"
)

const (
	defaultKMSKey = "kms_data"
	// SSKey key name of Signing secret
	SSKey = "SigningSecret"
	// TokenKey key name of slack token
	TokenKey = "Token"
)

// SlackHanlder config struct
type SlackHanlder struct {
	SlackAPI *slack.Client
	// SlackSS slack siging secret
	// https://api.slack.com/docs/verifying-requests-from-slack#app_management_updates
	SlackSS string

	// KMS
	KmsEnabled bool   // Use KMS Encrypt parameters
	KmsKeyID   string // master KeyID
	KmsKey     string // url param key name
	KmsSvc     kmsiface.KMSAPI

	// extra kvs
	ExtraKVS map[string]string
	// function of event handler
	EventHandlerFunc func(s *SlackHanlder, request RequestData) (events.APIGatewayProxyResponse, error)
}

// RequestData request and params
type RequestData struct {
	events.APIGatewayProxyRequest
	slackevents.EventsAPIEvent
	CbEvent *slackevents.EventsAPICallbackEvent
	KVS     map[string]string
	*SlackHanlder
}

func defaultEventHandler(s *SlackHanlder, request RequestData) (events.APIGatewayProxyResponse, error) {
	switch ev := request.InnerEvent.Data.(type) {
	case *slackevents.MessageEvent:
	case *slack.ChannelCreatedEvent:
		log.Printf("ok %T", ev)
	}
	log.Printf("event type: %T", request.InnerEvent.Data)
	return events.APIGatewayProxyResponse{StatusCode: 200}, nil
}

// GetValue get value from map[string]string
func GetValue(m map[string]string, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if ok {
		return v
	}
	return ""
}

func urlVerify(request RequestData) (events.APIGatewayProxyResponse, error) {
	var r slackevents.ChallengeResponse
	if err := json.Unmarshal([]byte(request.Body), &r); err != nil {
		log.Printf("Unmarshal request.Body err:%s, body: %s", err, request.Body)
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, err
	}
	resVerify, err := json.Marshal(slackevents.ChallengeResponse{Challenge: r.Challenge})
	if err != nil {
		log.Printf("json.Marshal(ChallengeResponse) err:%s, body: %s", err, request.Body)
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, err
	}
	log.Printf("ChallengeResponse OK request body: %s, response body: %s", request.Body, string(resVerify))
	return events.APIGatewayProxyResponse{Body: string(resVerify), StatusCode: 200}, nil
}

func (s *SlackHanlder) callbackEventHandler(request RequestData) (events.APIGatewayProxyResponse, error) {
	var ok bool
	request.CbEvent, ok = request.Data.(*slackevents.EventsAPICallbackEvent)
	if !ok {
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError},
			errors.New("do not EventsAPICallbackEvent data type")
	}
	return s.EventHandlerFunc(s, request)
}

func (s *SlackHanlder) init() {
	if s.EventHandlerFunc == nil {
		s.EventHandlerFunc = defaultEventHandler
	}
	if s.KmsKey == "" {
		s.KmsKey = defaultKMSKey
	}
}

// Handler main APIGateway handler
func (s *SlackHanlder) Handler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	s.init()
	reqData := RequestData{APIGatewayProxyRequest: request, KVS: map[string]string{}, SlackHanlder: s}
	j, err := json.Marshal(request)
	if err != nil {
		log.Printf("Marshal request err: %s request:%# v", err, j)
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, err
	}
	log.Printf("request: %s", j)
	log.Printf("body: %s", request.Body)

	if s.KmsEnabled {
		encoded, ok := request.QueryStringParameters[s.KmsKey]
		if !ok {
			log.Printf("not found '%s'", s.KmsKey)
			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, nil
		}
		reqData.KVS, err = s.DecryptKMS(encoded)
		if err != nil {
			log.Printf("DecryptKMS err:%s", err)
			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, err
		}
		s.SlackSS = GetValue(reqData.KVS, SSKey)
	}
	timestamp := GetValue(request.Headers, "X-Slack-Request-Timestamp")
	signature := GetValue(request.Headers, "X-Slack-Signature")
	reqData.EventsAPIEvent, err = slacksigverify.ParseEvent(
		json.RawMessage(request.Body), s.SlackSS, timestamp, request.Body, signature,
	)
	if err != nil {
		log.Printf("ParseEvent err:%s, body: %s", err, request.Body)
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, err
	}
	switch reqData.EventsAPIEvent.Type {
	case slackevents.URLVerification:
		return urlVerify(reqData)
	case slackevents.CallbackEvent:
		return s.callbackEventHandler(reqData)
	}
	return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError},
		fmt.Errorf("Unknown APIEvnetType:%s", reqData.EventsAPIEvent.Type)
}
