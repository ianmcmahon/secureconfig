package secureconfig

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type SecureConfig struct {
	Key     *rsa.PrivateKey `json:"-"`
	Secure  secureTuple     `json:"secure"`
	Private secureTuple     `json:"private"`
}

type secureTuple struct {
	Data      interface{} `json:"data"`
	Signature []byte      `json:"signature"`
}

type privateTuple struct {
	Data          interface{} `json:"-"`
	EncryptedData []byte      `json:"data"`
	Signature     []byte      `json:"signature"`
}

func SecureConfigWithPrivateKey(key *rsa.PrivateKey) *SecureConfig {
	return &SecureConfig{
		Key: key,
	}
}

func (sc *SecureConfig) SetSecureData(data interface{}) error {
	sc.Secure.Data = data
	// marshal it all into a byte format, hash it, sign it, store the signature

	b, err := json.Marshal(sc.Secure.Data)
	if err != nil {
		return err
	}

	fmt.Printf("marshalled data: %s\n", b)

	hashed := sha256.Sum256(b)

	sig, err := rsa.SignPSS(rand.Reader, sc.Key, crypto.SHA256, hashed[:], nil)
	if err != nil {
		return err
	}

	sc.Secure.Signature = make([]byte, len(sig)*2)
	hex.Encode(sc.Secure.Signature, sig)

	return nil
}

func (sc *SecureConfig) SetPrivateData(data interface{}) {
	sc.Private.Data = data
	// marshal it all into a byte format, encrypt it, hash it, sign it, store the signature
}
