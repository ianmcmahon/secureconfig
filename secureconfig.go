package secureconfig

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
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

	hash := crypto.Hash(crypto.SHA256).New().Sum(b)

	fmt.Printf("hash: %v\n", hash)

	sig, err := rsa.SignPSS(rand.Reader, sc.Key, crypto.Hash(crypto.SHA256), hash, nil)
	if err != nil {
		return err
	}

	fmt.Printf("sig: %v\n", sig)

	sc.Secure.Signature = []byte("foo")

	return nil
}

func (sc *SecureConfig) SetPrivateData(data interface{}) {
	sc.Private.Data = data
	// marshal it all into a byte format, encrypt it, hash it, sign it, store the signature
}
