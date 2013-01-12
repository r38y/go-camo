// go-camo daemon (go-camod)
package main

import (
	"encoding/json"
	"fmt"
	"github.com/cactus/go-camo/camoproxy/encoding"
	flags "github.com/jessevdk/go-flags"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"strings"
)

func main() {

	// command line flags
	var opts struct {
		ConfigFile string `short:"c" long:"config" description:"JSON Config File"`
		HmacKey    string `short:"k" long:"key" description:"HMAC key"`
		Encode     bool   `short:"e" long:"encode" description:"Encode a url and print result"`
		Decode     bool   `short:"d" long:"decode" description:"Decode a url and print result"`
		Base64     bool   `long:"base64" description:"Use Base64 encoding for url. Only relevant for Encode."`
		Hex        bool   `long:"hex" description:"Use hex encoding for url. Only relevant for Encode."`
		Prefix     string `long:"prefix" default:"" description:"Optional url prefix used by encode output"`
	}

	// parse said flags
	args, err := flags.Parse(&opts)
	if err != nil {
		if e, ok := err.(*flags.Error); ok {
			if e.Type == flags.ErrHelp {
				os.Exit(0)
			}
		}
		os.Exit(1)
	}

	// clear log prefix -- not needed for tool
	log.SetFlags(0)

	// Anonymous struct Container for holding configuration parameters
	// parsed from JSON config file.
	config := struct {
		HmacKey string
	}{}

	if opts.ConfigFile != "" {
		b, err := ioutil.ReadFile(opts.ConfigFile)
		if err != nil {
			log.Fatal("Could not read configFile", err)
		}
		err = json.Unmarshal(b, &config)
		if err != nil {
			log.Fatal("Could not parse configFile", err)
		}
	}

	if opts.Encode == true && opts.Decode == true {
		log.Fatal("Encode and Decode are mutually exclusive. Doing nothing.")
	}

	if opts.Encode == false && opts.Decode == false {
		log.Fatal("No action requested. Doing nothing.")
	}

	// flags override config file
	if opts.HmacKey != "" {
		config.HmacKey = opts.HmacKey
	}

	if len(args) == 0 {
		log.Fatal("No url argument provided")
	}

	oUrl := args[0]
	if oUrl == "" {
		log.Fatal("No url argument provided")
	}

	hmacKeyBytes := []byte(config.HmacKey)

	var encoder encoding.Encoder
	var decoder encoding.Decoder
	var pathPrefix string
	if opts.Base64 {
		encoder = encoding.EncodeBase64Url
		decoder = encoding.DecodeBase64Url
		pathPrefix = "/b"
	}
	if !opts.Base64 || opts.Hex {
		encoder = encoding.EncodeHexUrl
		decoder = encoding.DecodeHexUrl
		pathPrefix = ""
	}

	if opts.Encode == true {
		outUrl := encoder(&hmacKeyBytes, oUrl)
		fmt.Println(opts.Prefix + pathPrefix + outUrl)
	}

	if opts.Decode == true {
		u, err := url.Parse(oUrl)
		if err != nil {
			log.Fatal(err)
		}
		var digest, encurl string
		if strings.HasPrefix(u.Path, "/b/") {
			decoder = encoding.DecodeBase64Url
			comp := strings.SplitN(u.Path, "/", 4)
			digest = comp[2]
			encurl = comp[3]
		} else {
			decoder = encoding.DecodeHexUrl
			comp := strings.SplitN(u.Path, "/", 3)
			digest = comp[1]
			encurl = comp[2]
		}
		decUrl, valid := decoder(&hmacKeyBytes, digest, encurl)
		if !valid {
			log.Fatal("hmac is invalid")
		}
		log.Println(decUrl)
	}
}
