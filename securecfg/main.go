package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"

	"github.com/ianmcmahon/secureconfig"
	"github.com/urfave/cli"
)

// by default use the key in ~/.ssh/id_rsa for signing
// have a flag to override the signing key
// require a pubkey passed in via flag for encryption
// encrypted data ("private") is specified by a flag for a filename
// and/or json blob on the cli, or maybe even keypairs
func main() {
	usr, err := user.Current()
	if err != nil {
		fmt.Errorf("Error getting current user: %v\n", err)
	}

	defaultSigningKey := fmt.Sprintf("%s/.ssh/id_rsa", usr.HomeDir)

	app := cli.NewApp()
	app.Name = "securecfg"
	app.Usage = "manage secure and private config data"
	app.Commands = []cli.Command{
		cli.Command{
			Name:   "sign",
			Usage:  "sign the secure data in a config file",
			Action: signAction,
			Flags: []cli.Flag{
				cli.StringFlag{Name: "signing-key, sk", Value: defaultSigningKey},
				cli.StringFlag{Name: "encryption-key, ek"},
			},
		},
		cli.Command{
			Name:   "verify",
			Usage:  "verify the signature of a secure config",
			Action: verifyAction,
		},
	}

	app.Run(os.Args)
}

func signAction(c *cli.Context) error {
	if c.NArg() == 0 {
		// todo: sign from stdin to stdout
		return fmt.Errorf("No files to sign!")
	}

	signingKey, err := getKey(c.String("signing-key"))
	if err != nil {
		return fmt.Errorf("Couldn't load key from %s: %v", c.String("signing-key"), err)
	}
	fmt.Printf("using signing key: %s\n", c.String("signing-key"))

	fmt.Printf("signing files: %v\n", c.Args())

	errs := []error{}

	for _, f := range c.Args() {
		if err := signConfig(f, signingKey); err != nil {
			errs = append(errs, fmt.Errorf("Error signing %s: %v\n", f, err))
		}
	}

	if len(errs) > 0 {
		return cli.NewMultiError(errs...)
	}

	return nil
}

func verifyAction(c *cli.Context) error {
	fmt.Printf("in verify\n")
	return nil
}

func getKey(filename string) (*rsa.PrivateKey, error) {
	filename, err := filepath.Abs(filename)
	if err != nil {
		return nil, err
	}

	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	for len(b) > 0 {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			return nil, fmt.Errorf("no PEM blocks found")
		}

		if block.Type != "RSA PRIVATE KEY" {
			continue
		}

		if x509.IsEncryptedPEMBlock(block) {
			fmt.Printf("contains an encrypted key.  Will need your password to decrypt, but we haven't implemented that garbage yet.  Skipping!\n")
		}

		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			fmt.Printf("error parsing PKCS1 key: %v\n", err)
			continue
		}

		return key, nil
	}

	return nil, fmt.Errorf("No usable rsa key found")
}

func signConfig(filename string, signingKey *rsa.PrivateKey) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	var data interface{}

	scOrig, err := secureconfig.LoadSecureConfig(nil, nil, file)
	if err != nil {
		fmt.Printf("Couldn't load %s as an existing SecureConfig, importing anew\n")

		if _, err := file.Seek(0, 0); err != nil {
			return err
		}

		dec := json.NewDecoder(file)
		if err := dec.Decode(&data); err != nil {
			return err
		}
	} else {
		fmt.Printf("loaded: %v\n", scOrig)
		if _, err := scOrig.GetSecureData(data); err != nil {
			return err
		}
	}

	file.Close() // if we make it this far, we've closed the original file and the defer works for the reopening.

	fmt.Printf("data: %v\n", data)

	sc := secureconfig.NewSecureConfig(signingKey, nil)

	if err := sc.SetSecureData(data); err != nil {
		return err
	}

	file, err = os.Create(filename)
	if err != nil {
		return err
	}

	return sc.SavePretty(file)
}
