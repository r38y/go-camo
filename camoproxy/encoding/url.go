package encoding

import (
	"crypto/hmac"
	"crypto/sha1"
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
	var encoder sEncoder
	var decoder sDecoder
	encoder = hex.EncodeToString
	decoder = hex.DecodeString
	return decodeUrl(hmackey, encoder, decoder, encdig, encurl)
}

// DecodeUrl ensures the url is properly verified via HMAC, and then
// decodes the base64 url, returning the url (if valid) and whether the
// HMAC was verified.
func DecodeBase64Url(hmackey *[]byte, encdig string, encurl string) (string, bool) {
	encoder := func(src []byte) string {
		return strings.TrimRight(base64.URLEncoding.EncodeToString(src), "=")
	}
	decoder := func(s string) ([]byte, error) {
		return base64.URLEncoding.DecodeString(strings.TrimRight(s, "="))
	}
	return decodeUrl(hmackey, encoder, decoder, encdig, encurl)
}

func decodeUrl(hmackey *[]byte, encoder sEncoder, decoder sDecoder, encdig string, encurl string) (surl string, valid bool) {
	urlBytes, err := decoder(encurl)
	if err != nil {
		gologit.Debugln("Bad Base64 Decode", encurl)
		return
	}
	mac := hmac.New(sha1.New, *hmackey)
	mac.Write(urlBytes)
	macSum := encoder(mac.Sum(nil))
	if macSum != encdig {
		gologit.Debugf("Bad signature: %s != %s\n", macSum, encdig)
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
