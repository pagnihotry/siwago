package siwago

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

//struct for JWT Header
type JWTTokenHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

//struct for JWT Body
type JWTTokenBody struct {
	Iss            string `json:"iss"`
	Iat            int64  `json:"iat"`
	Exp            int64  `json:"exp"`
	Aud            string `json:"aud"`
	Sub            string `json:"sub"`
	AtHash         string `json:"at_hash"`
	Email          string `json:"email"`
	EmailVerified  string `json:"email_verified"`
	IsPrivateEmail string `json:"is_private_email"`
	RealUserStatus int64  `json:"real_user_status"`
	AuthTime       int64  `json:"auth_time"`
	Nonce          string `json:"nonce"`
}

//struct to hold the decoded idtoken
type SiwaIdToken struct {
	Header    *JWTTokenHeader
	Body      *JWTTokenBody
	Signature []byte
	Valid     bool
}

//struct for token returned from apple
type Token struct {
	//(Reserved for future use) A token used to access allowed data. Currently, no data set has been defined for access.
	AccessToken string `json:"access_token"`
	//The type of access token. It will always be bearer.
	TokenType string `json:"token_type"`
	//The amount of time, in seconds, before the access token expires.
	ExpiresIn int64 `json:"expires_in"`
	//The refresh token used to regenerate new access tokens. Store this token securely on your server.
	RefreshToken string `json:"refresh_token"`
	//A JSON Web Token that contains the user’s identity information.
	IdToken string `json:"id_token"`
	//Set if ErrorResponse is recieved
	//A string that describes the reason for the unsuccessful request. The string consists of a single allowed value.
	//Possible values: invalid_request, invalid_client, invalid_grant, unauthorized_client, unsupported_grant_type, invalid_scope
	Error string `json:"error"`
	//After the token is fetched from apple, id token is validated
	//this field stores the result of the validation check
	Valid bool `json:"_"`
	//The decoded Id token
	//Holds the decoded JWT Header, Body, Signature and result of validity check
	DecodedIdToken *SiwaIdToken `json:"_"`
}

func (self Token) String() string {
	return fmt.Sprintf("AccessToken: %v, TokenType: %v, ExpiresIn:%v, RefreshToken:%v, IdToken:%v, Error:%v, Valid:%v",
		self.AccessToken, self.TokenType, self.ExpiresIn, self.RefreshToken, self.IdToken, self.Error, self.Valid)
}

//function to verify idtoken signature for apple published public key
func verifyAppleRSA256(message string, signature []byte, kid string) error {
	//get the public key
	rsaPublicKey, err := getApplePublicKeyObject(kid, "RS256")
	if err != nil {
		return err
	}

	//if key found, validate
	if rsaPublicKey != nil {
		bytesToHash := []byte(message)
		//get hash
		hashed := sha256.Sum256(bytesToHash)
		err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, hashed[:], signature)
		if err != nil {
			return err
		}
	}
	return nil
}

//validates idToken without nonce check
func ValidateIdToken(aud string, idToken string) (*SiwaIdToken, string) {
	return ValidateIdTokenWithNonce(aud, idToken, "")
}

//validates idtoken
//more info: https://developer.apple.com/documentation/signinwithapplerestapi/verifying_a_user
func ValidateIdTokenWithNonce(aud string, idToken string, nonce string) (*SiwaIdToken, string) {

	//initialize the token object
	var siwaIdToken *SiwaIdToken = &SiwaIdToken{Valid: false}

	if idToken == "" {
		return siwaIdToken, "empty_token"
	}

	//split and decode token
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return siwaIdToken, "invalid_format_missing_parts"
	}
	jsonHeaderB, err := base64UrlDecode(parts[0])
	if err != nil {
		return siwaIdToken, "invalid_format_header_base64_decode_failed error:" + err.Error()
	}
	var jwtHeader JWTTokenHeader
	err = json.Unmarshal(jsonHeaderB, &jwtHeader)
	if err != nil {
		return siwaIdToken, "invalid_format_header_json_decode_failed error:" + err.Error()
	}
	jsonBodyB, err := base64UrlDecode(parts[1])
	if err != nil {
		return siwaIdToken, "invalid_format_body_base64_decode_failed error:" + err.Error()
	}
	var jwtBody JWTTokenBody
	err = json.Unmarshal(jsonBodyB, &jwtBody)
	if err != nil {
		return siwaIdToken, "invalid_format_body_json_decode_failed error:" + err.Error()
	}

	//the basic validation tests pass. Now check if the contents of token are valid
	var reason string
	var valid bool = true

	//Verify the nonce for the authentication
	//if idtoken had nonce, the check will fail
	if jwtBody.Nonce != "" && jwtBody.Nonce != nonce {
		reason = reason + "nonce_check_failed"
		valid = false
	}

	//Verify that the iss field contains https://appleid.apple.com
	if jwtBody.Iss != "https://appleid.apple.com" {
		reason = reason + " iss_check_failed"
		valid = false
	}

	//Verify that the aud field is the developer’s client_id
	if jwtBody.Aud != aud {
		reason = reason + " aud_check_failed"
		valid = false
	}

	//Verify that the time is earlier than the exp value of the token
	if jwtBody.Exp < time.Now().Unix() {
		reason = reason + " expiry_in_past"
		valid = false
	}

	//Verify the JWS E256 signature using the server’s public key
	var decodedSignature []byte
	decodedSignature, err = base64UrlDecode(parts[2])
	if err != nil {
		reason = reason + fmt.Sprintf(" signature_base64_decode_failed [%s] ", err)
		valid = false
	} else {
		if err := verifyAppleRSA256(parts[0]+"."+parts[1], decodedSignature, jwtHeader.Kid); err != nil {
			reason = reason + fmt.Sprintf(" signature_verification_failed [%s] ", err)
			valid = false
		}
	}

	//set the values of parsed token into the id token object
	siwaIdToken.Header = &jwtHeader
	siwaIdToken.Body = &jwtBody
	siwaIdToken.Valid = valid
	siwaIdToken.Signature = decodedSignature

	return siwaIdToken, reason
}
