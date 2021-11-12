# Siwago

Siwago is an implementation of authenticating "Sign in with Apple" tokens with Apple servers. It implements the validation and generation of tokens outlined at this link: https://developer.apple.com/documentation/signinwithapplerestapi/generate_and_validate_tokens

This repo contains the functionality to validate the authorization code provided to the client while signing in with Apple and to generate access_token. This is intended to be used on the server side.

This implementation has no external dependencies and manages encoding and singing using the go provided core functions.

## Install & Usage

### Install
Execute `go get github.com/pagnihotry/siwago`. This installs the package in your `$GOPATH`. 

### Usage
Get the tokens from Apple in the following three steps:
1. Initialize SiwaConfig object `siwago.GetObject(KID, TEAMID, BUNDLEID, duration, nonce)`
2. Set the private key in one of the following ways
    - Using file: `siwagoObj.SetSecretP8File("/etc/keys/AuthKey_3UHT5POLK9.p8")`
    - Using file contents as string: `siwagoObj.SetSecretP8String("//-----BEGIN PRIVATE KEY-----\njkfweshjdjkhjsbjvguybjebvuewkvbbhj+jbdhbjhbvjhbvjhbvbjvbvjvagcve\njkfweshjdjkhjsbjvguybje/vuewkvbbhjdjbdhbjhbvjhbvjhbvbjvbvjvagcve\njkfweshjdjkhjsbjvguybjebvuewkvbbhj+jbdhbjhbvjhbvjhbvbjvbvjvagcve\njkfweshj\n-----END PRIVATE KEY-----")`
    - Using file contents as []byte: `siwagoObj.SetSecretP8Bytes(byteContents)`
3. Exchange the code for a token `token, err :=siwagoObj.ExchangeAuthCode(code, redirectUri)` `redirectUri` can be `""` if it does not apply

Alternatively, you can split the secret generation and token steps as follows:
1. Initialize the SiwaConfig object `siwago.GetObject(KID, TEAMID, BUNDLEID, duration, "")`.
2. Generate a secret key: `secret, err := siwagoObj.GetClientSecret()`.
3. (Possibly in a separate process) initialize a new SiwaConfig with just the
   client secret: `siwago.GetObjectWithSecret(BUNDLEID, nonce, secret)`.
4. Token exchange: `token, err :=siwagoObj.ExchangeAuthCode(code, redirectUri)`


If there is an error `token.Error` is set to the error recieved from Apple. More info: https://developer.apple.com/documentation/signinwithapplerestapi/errorresponse 

In case of success token object is populated with the access token, refresh token, etc. from Apple. More info: https://developer.apple.com/documentation/signinwithapplerestapi/tokenresponse

## Details

### SiwaConfig object
This object holds the app configuration that will be used to generate JWT token. This token can be initialized using a helper function `GetObject(keyId string, teamId string, bundleId string, d time.Duration)` or directly `SiwaConfig{KeyId: keyId, TokenDelta: d, TeamId: teamId, BundleId: bundleId}`

```go
type SiwaConfig struct {
    //key Id from Certificates, Identifiers & Profiles on developers.apple.com
    KeyId           string 
    //duration for which you would want the generated client_secret jwt token to be valid.
    //Can not be more than 15777000 (6 months in seconds) from the Current Unix Time on the server.
    TokenDelta      time.Duration 
    //Team Id that is configured with Key, 
    //can also ne found in Certificates, Identifiers & Profiles on developers.apple.com
    TeamId          string 
    //bundleId for product com.companyname.product
    BundleId        string 
    //contents of the p8 file
    PemFileContents []byte 
    //nonce is set while making the request to generate authorization_code. If you dont use it, keep it an empty string
    Nonce           string
}
```

### Setting Secret

The signing secret or the private key can be set with a file on the disk - .p8 file downloaded from the Apple Developer website, or as a `string` or `[]byte`. 

Private key file format:
```
-----BEGIN PRIVATE KEY-----
jkfweshjdjkhjsbjvguybjebvuewkvbbhj+jbdhbjhbvjhbvjhbvbjvbvjvagcve
jkfweshjdjkhjsbjvguybje/vuewkvbbhjdjbdhbjhbvjhbvjhbvbjvbvjvagcve
jkfweshjdjkhjsbjvguybjebvuewkvbbhj+jbdhbjhbvjhbvjhbvbjvbvjvagcve
jkfweshj
-----END PRIVATE KEY-----
```

#### File
```go
func (self *SiwaConfig) SetSecretP8File(p8Filename string) error
```

#### string
```go
func (self *SiwaConfig) SetSecretP8String(p8Contents string)
```

#### []byte
```go
func (self *SiwaConfig) SetSecretP8Bytes(p8Contents []byte)
```

### Token object

The token object is returned by the `ExchangeAuthCode` method. This contains the response from Apple. The API returns a [TokenResponse](https://developer.apple.com/documentation/signinwithapplerestapi/tokenresponse) or [ErrorResponse](https://developer.apple.com/documentation/signinwithapplerestapi/errorresponse). If there is an error, the `Token.Error` is set with the message, else all the other fields are populated.

To check for errors, see if `.Error` is `""`.

```go
type Token struct {
    //(Reserved for future use) A token used to access allowed data. Currently, no data set has been defined for access.
    AccessToken  string `json:"access_token"`
    //The type of access token. It will always be bearer.
    TokenType    string `json:"token_type"`
    //The amount of time, in seconds, before the access token expires.
    ExpiresIn    int64  `json:"expires_in"`
    //The refresh token used to regenerate new access tokens. Store this token securely on your server.
    RefreshToken string `json:"refresh_token"`
    //A JSON Web Token that contains the user’s identity information.
    IdToken      string `json:"id_token"`
    //Set if ErrorResponse is recieved
    //A string that describes the reason for the unsuccessful request. The string consists of a single allowed value.
    //Possible values: invalid_request, invalid_client, invalid_grant, unauthorized_client, unsupported_grant_type, invalid_scope
    Error        string `json:"error"`
    //After the token is fetched from apple, id token is validated
    //this field stores the result of the validation check
    Valid bool `json:"_"`
    //The decoded Id token
    //Holds the decoded JWT Header, Body, Signature and result of validity check
    DecodedIdToken *SiwaIdToken `json:"_"`
}
```

#### Token Validation

The `id_token` returned by apple is validated as follows:

- Verify the JWS E256 signature using the server’s public key
- Verify the nonce for the authentication
- Verify that the iss field contains https://appleid.apple.com
- Verify that the aud field is the developer’s client_id
- Verify that the time is earlier than the exp value of the token

This is as per the guidelines on apple developer website at https://developer.apple.com/documentation/signinwithapplerestapi/verifying_a_user

## Sample code

Here is a sample implementation for checking the token
```go
package main

import (
    "fmt"
    "time"

    "github.com/pagnihotry/siwago"
)

const KID = "3UHT5POLK9"
const BUNDLEID = "com.company.product"
const TEAMID = "JSFD9L6MCB"

func main() {
    var code string
    var d time.Duration
    var siwagoObj *siwago.SiwaConfig
    var token *siwago.Token
    var err error

    code = "ce47cc89t73da4d3897905f349d404hq5.0.nrrxy.H2Pt0rU0wi0VdumPWM9pEg"
    d = 30 * 24 * time.Hour
    siwagoObj = siwago.GetObject(KID, TEAMID, BUNDLEID, d, "test_nonce")
    err = siwagoObj.SetSecretP8File("/etc/keys/AuthKey_3UHT5POLK9.p8")
    if err != nil {
        fmt.Println(err.Error())
        return
    }

    token, err = siwagoObj.ExchangeAuthCode(code, "")
    //if there was an error and token is not nil, it can be used to get more information about the failure
    //to check if the apple request failed or token validation failed
    if err != nil {
        if token == nil {
            fmt.Println("Error with exchanging token, token is nil.", err.Error())
        } else if token.Error != "" {
            fmt.Println("Error while requesting token error:", token.Error)
        } else if !token.Valid {
            fmt.Println("Invalid token", err.Error(), token.String())
        }
        return
    }

    fmt.Println("Generated Valid Token:", token.String())
}

```
