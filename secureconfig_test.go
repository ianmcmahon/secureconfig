package secureconfig

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

type testSecureConfigStructure struct {
	Foo string            `json:"foo"`
	Bar []int             `json:"bar"`
	Baz map[string]string `json:"baz"`
}

func TestSecureConfig(t *testing.T) {
	signedCfg := &testSecureConfigStructure{
		Foo: "abc",
		Bar: []int{1, 2, 3},
		Baz: map[string]string{
			"quux": "xyzzy",
		},
	}

	// this represents my private ssh key, used for signing configs
	myKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
	}

	// this represents the host's keypair, private data will be encrypted so only the host key can read it
	hostKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
	}

	sc := NewSecureConfig(myKey, &hostKey.PublicKey)

	err = sc.SetSecureData(signedCfg)
	if err != nil {
		t.Error(err)
	}

	err = sc.SetPrivateData(signedCfg)
	if err != nil {
		t.Error(err)
	}

	buf := new(bytes.Buffer)

	sc.Save(buf)

	// fmt.Printf("%s\n", buf.String())

	sc2, err := LoadSecureConfig(&myKey.PublicKey, hostKey, buf)
	if err != nil {
		t.Error(err)
		return
	}

	signedConfig := &testSecureConfigStructure{}
	valid, err := sc2.GetSecureData(signedConfig)
	if err != nil {
		t.Error(err)
	}

	if !valid {
		t.Error("Secure signature did not verify")
	}

	// fmt.Printf("secure config: %v\n", signedConfig)

	privateConfig := &testSecureConfigStructure{}
	valid, err = sc2.GetPrivateData(privateConfig)
	if err != nil {
		t.Error(err)
	}

	if !valid {
		t.Error("Private signature did not verify")
	}

	// fmt.Printf("private config: %v\n", privateConfig)
}
