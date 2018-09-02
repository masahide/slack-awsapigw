package slackawsapigw

import (
	"encoding/json"
	"fmt"

	"github.com/masahide/kmscrypt"
)

// DecryptKMS decrypt params
func (s *SlackHanlder) DecryptKMS(encoded string) (map[string]string, error) {
	plaintext, err := kmscrypt.AESDecrypt(s.KmsSvc, s.KmsKey, encoded)
	if err != nil {
		return nil, err
	}
	valueMap := map[string]string{}
	if err := json.Unmarshal([]byte(plaintext), &valueMap); err != nil {
		return nil, fmt.Errorf("Unmarshal err:%s, plaintext: %s", err, plaintext)
	}
	return valueMap, nil
}

// EncryptKMS encrypt params
func (s *SlackHanlder) EncryptKMS(params map[string]string) (string, error) {
	b, err := json.Marshal(params)
	if err != nil {
		return "", fmt.Errorf("Marshal err:%s, params: %v", err, params)
	}
	return kmscrypt.AESEncrypt(s.KmsSvc, s.KmsKeyID, s.KmsKey, string(b))
}
