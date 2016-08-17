package secureconfig

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"testing"
)

type testSecureConfigStructure struct {
	Foo string            `json:"foo"`
	Bar []int             `json:"bar"`
	Baz map[string]string `json:"baz"`
}

func TestCreate(t *testing.T) {
	signedCfg := &testSecureConfigStructure{
		Foo: "abc",
		Bar: []int{1, 2, 3},
		Baz: map[string]string{
			"quux": "xyzzy",
		},
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
	}

	sc := SecureConfigWithPrivateKey(key)

	err = sc.SetSecureData(signedCfg)
	if err != nil {
		t.Error(err)
	}

	b, err := json.Marshal(sc)
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("%s\n", b)
}
