package siwago

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"time"
)

const APPLE_KEYS_URL = "https://appleid.apple.com/auth/keys"

//global cache for fast subsequent fetching
var applePublicKeyObject map[string]*rsa.PublicKey

//key object fetched from APPLE_KEYS_URL
type AppleKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use":`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func init() {
	applePublicKeyObject = make(map[string]*rsa.PublicKey)
}

//make request to APPLE_KEYS_URL to get the keys
func getApplePublicKeys() ([]AppleKey, error) {

	var c http.Client
	var req *http.Request
	var resp *http.Response
	var bodyContents []byte
	var err error
	var keys struct {
		Keys []AppleKey `json:"keys"`
	}

	//make http client
	c = http.Client{Timeout: 5 * time.Second}
	req, err = http.NewRequest("GET", APPLE_KEYS_URL, nil)
	if err != nil {
		return nil, err
	}

	//perform request
	resp, err = c.Do(req)
	if err != nil {
		return nil, err
	}

	//read response
	bodyContents, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	//unmarshal into struct
	err = json.Unmarshal(bodyContents, &keys)
	if err != nil {
		return nil, err
	}

	//return the keys fetched
	return keys.Keys, nil
}

//get apple public key from the keys array
func getApplePublicKey(kid string) (*AppleKey, error) {
	//get the apple published public keys
	keys, err := getApplePublicKeys()
	if err != nil {
		return nil, err
	}
	if keys == nil {
		return nil, errors.New("no keys returned by Apple")
	}

	//extract the key with specified kid
	for _, key := range keys {
		if key.Kid == kid {
			//stop and return if found
			return &key, nil
		}
	}

	return nil, fmt.Errorf("could not find key %q", kid)
}

//locally cache and get apple rsa.PublicKey object
func getApplePublicKeyObject(kid string, alg string) (*rsa.PublicKey, error) {

	//if computed earlier, return the object
	if key, ok := applePublicKeyObject[kid+alg]; ok {
		return key, nil
	}

	//get the key with specified kid from the web
	applePublicKey, err := getApplePublicKey(kid)
	if err != nil {
		return nil, err
	}
	//if key found, contrust a rsa.PublikKey object
	if applePublicKey.Alg == alg {
		key := getPublicKeyObject(applePublicKey.N, applePublicKey.E)
		applePublicKeyObject[kid+alg] = key
		return key, nil
	}
	return nil, fmt.Errorf("Apple public key had wrong alg: wanted %q but found %q", alg, applePublicKey.Alg)
}

//function to generate rsa.PublicKey object from encoded modulo and exponent
func getPublicKeyObject(base64urlEncodedN string, base64urlEncodedE string) *rsa.PublicKey {

	var pub rsa.PublicKey
	var decE, decN []byte
	var eInt int
	var err error

	//get the modulo
	decN, err = base64.RawURLEncoding.DecodeString(base64urlEncodedN)
	if err != nil {
		return nil
	}
	pub.N = new(big.Int)
	pub.N.SetBytes(decN)
	//get exponent
	decE, err = base64.RawURLEncoding.DecodeString(base64urlEncodedE)
	if err != nil {
		return nil
	}
	//convert the bytes into int
	for _, v := range decE {
		eInt = eInt << 8
		eInt = eInt | int(v)
	}
	pub.E = eInt

	return &pub
}

//generate private key from pem encoded string
func getPrivKey(pemEncoded []byte) (*ecdsa.PrivateKey, error) {

	var block *pem.Block
	var x509Encoded []byte
	var err error
	var privateKeyI interface{}
	var privateKey *ecdsa.PrivateKey
	var ok bool

	//decode the pem format
	block, _ = pem.Decode(pemEncoded)
	//check if its is private key
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("Failed to decode PEM block containing private key")
	}

	//get the encoded bytes
	x509Encoded = block.Bytes

	//genrate the private key object
	privateKeyI, err = x509.ParsePKCS8PrivateKey(x509Encoded)
	if err != nil {
		return nil, errors.New("Private key decoding failed. " + err.Error())
	}
	//cast into ecdsa.PrivateKey object
	privateKey, ok = privateKeyI.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("Private key is not ecdsa key")
	}

	return privateKey, nil
}

// Decode decodes base64url string to byte array
// just a wrapper function
func base64UrlDecode(data string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(data)
}

// Encode encodes given byte array to base64url string
// just a wrapper function
func base64UrlEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
