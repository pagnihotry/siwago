package siwago

import "testing"

func TestAppleKeys(t *testing.T) {

	//multiple keys from apple
	kids := []string{"86D88Kf", "eXaunmL"}

	for _, kid := range kids {
		t.Logf("Testing kid=%s", kid)
		//check for the apple key object
		applekey := getApplePublicKey(kid)
		if applekey.Kid != kid {
			t.Errorf("Invalid Key " + kid)
		}
		//check RSA object
		key := getApplePublicKeyObject(kid, "RS256")
		if key.N == nil {
			t.Errorf("Invalid Key " + kid)
		}
	}
}
