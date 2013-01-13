package encoding

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"github.com/cactus/gologit"
	"strings"
)

type sEncoder func([]byte) string
type sDecoder func(string) ([]byte, error)
type Encoder func(*[]byte, string) string
type Decoder func(*[]byte, string, string) (string, bool)

// DecodeUrl ensures the url is properly verified via HMAC, and then
// decodes the hex url, returning the url (if valid) and whether the
// HMAC was verified.
func DecodeHexUrl(hmackey *[]byte, encdig string, encurl string) (string, bool) {
	decoder := hex.DecodeString
	return decodeUrl(hmackey, decoder, encdig, encurl)
}

// DecodeUrl ensures the url is properly verified via HMAC, and then
// decodes the base64 url, returning the url (if valid) and whether the
// HMAC was verified.
func DecodeBase64Url(hmackey *[]byte, encdig string, encurl string) (string, bool) {
	decoder := func(s string) ([]byte, error) {
		if len(s) % 4 != 0 {
			s = s + strings.Repeat("=", (4 - (len(s) % 4)))
		}
		return base64.URLEncoding.DecodeString(s)
	}
	return decodeUrl(hmackey, decoder, encdig, encurl)
}

// DecodeUrl ensures the url is properly verified via HMAC,
// decodes the url with the provided decoder, returning the url (if valid) and
// whether the HMAC was verified.
func decodeUrl(hmackey *[]byte, decoder sDecoder, encdig string, encurl string) (surl string, valid bool) {
	urlBytes, err := decoder(encurl)
	if err != nil {
		gologit.Debugln("Bad URL decode", encurl)
		return
	}
	inMacSum, err := decoder(encdig)
	if err != nil {
		gologit.Debugln("Bad digest decode", encdig, err)
		return
	}

	mac := hmac.New(sha1.New, *hmackey)
	mac.Write(urlBytes)
	macSum := mac.Sum(nil)

	if subtle.ConstantTimeCompare(macSum, inMacSum) != 1 {
		gologit.Debugf("Bad signature: %x != %x\n", macSum, inMacSum)
		return
	}
	surl = string(urlBytes)
	valid = true
	return
}

// EncodeHexUrl takes an HMAC key and a url, and returns url
// path partial consisitent of signature and hex encoded url.
func EncodeHexUrl(hmacKey *[]byte, oUrl string) string {
	encoder := hex.EncodeToString
	return encodeUrl(hmacKey, encoder, oUrl)
}

// EncodeHexUrl takes an HMAC key and a url, and returns url
// path partial consisitent of signature and base64 encoded url.
func EncodeBase64Url(hmacKey *[]byte, oUrl string) string {
	encoder := func(src []byte) string {
		return strings.TrimRight(base64.URLEncoding.EncodeToString(src), "=")
	}
	return encodeUrl(hmacKey, encoder, oUrl)
}

// encodeUrl takes an HMAC key, an encoder function, and a url, and returns url
// path partial consisitent of signature and encoded url.
func encodeUrl(hmacKey *[]byte, encoder sEncoder, oUrl string) string {
	mac := hmac.New(sha1.New, *hmacKey)
	mac.Write([]byte(oUrl))
	macSum := encoder(mac.Sum([]byte{}))
	encodedUrl := encoder([]byte(oUrl))
	encurl := "/" + macSum + "/" + encodedUrl
	return encurl
}
