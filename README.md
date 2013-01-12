go-camo
=======

## About

Go version of [Camo][1] server.

[Camo][1] is a special type of image proxy that proxies non-secure images over
SSL/TLS. This prevents mixed content warnings on secure pages.

It works in conjunction with back-end code to rewrite image URLs and sign them
with an [HMAC][4].

## How it works

First you parse the original URL, generate an HMAC signature of it, then hex
encode it, and then place the pieces into the expected format replacing the
original image URL.

The client requests the URL to Go-Camo. Go-Camo validates the HMAC, decodes the
URL, requests the content and streams it to the client.

Here is some example python code that demonstrates generating an encoded URL:

    import hashlib
    import hmac
    def mk_camo_url(hmac_key, image_url, camo_host):
        if image_url.startswith("https:"):
            return image_url
        hexdigest = hmac.new(hmac_key, image_url, hashlib.sha1).hexdigest()
        hexurl = image_url.encode('hex')
        requrl = 'https://%s/%s/%s' % (camo_host, hexdigest, hexurl)
        return requrl

Here it is in action:

    >>> mk_camo_url("test", "http://golang.org/doc/gopher/frontpage.png", "img.example.org")
    'https://img.example.org/0f6def1cb147b0e84f39cbddc5ea10c80253a6f3/687474703a2f2f676f6c616e672e6f72672f646f632f676f706865722f66726f6e74706167652e706e67'

While Go-Camo will support proxying HTTPS images as well, for performance
reasons you may choose to filter HTTPS requests out from proxying, and let the
client simply fetch those as they are. The code example above does this.

Note that it is recommended to front Go-Camo with a CDN when possible.

## Differences from Camo

*   Go-Camo supports 'Path Format' url format only. Camo's "Query
    String Format" is not supported.
*   Go-Camo supports "allow regex host filters".
*   Go-Camo supports client http keep-alives.
*   Go-Camo provides native SSL support.
*   Go-Camo supports using more than one os thread (via GOMAXPROCS) without the
    need of multiple instances or additional proxying.
*   Go-Camo builds to a static binary. This makes deploying to large numbers
    of servers a snap.
*   Go-Camo supports a Base64 url encoding option (goal is reduction of url
    size).

## Building

Building requires `git` and `hg` (mecurial). They are used to fetch
dependencies. A functional [Go][3] installation is also required.

    # Set GOPATH if appropriate

    # get code and dependencies
    $ go get -d github.com/cactus/go-camo

    # build and install to GOPATH
    $ go install github.com/cactus/go-camo

    # as an alternative to the previous command, build and strip debug symbols.
    # this is useful for production, and reduces the resulting file size.
    $ go install -ldflags '-s' github.com/cactus/go-camo


## Running

    $ $GOPATH/bin/go-camo -c config.json

Go-Camo does not daemonize on its own. For production usage, it is recommended
to launch in a process supervisor, and drop privileges as appropriate.

Examples of supervisors include: [daemontools][5], [runit][6], [upstart][7],
[launchd][8], and many more.

For the reasoning behind lack of daemonization, see [daemontools/why][9]. In
addition, the code is much simpler because of it.

## Running under devweb

[Devweb][2] is useful for developing. To run under devweb:

    $ go get code.google.com/p/rsc/devweb
    $ PATH=.:$PATH $GOPATH/bin/devweb -addr=127.0.0.1:8080 github.com/cactus/go-camo/go-camo-devweb
    $ rm -f ./prox.exe  # devweb drops this file. clean it up

## Configuring

    $ $GOPATH/bin/go-camo -h
    Usage:
      go-camo [OPTIONS]

    Help Options:
      -h, --help          Show this help message

    Application Options:
      -c, --config        JSON Config File
      -k, --key           HMAC key
          --stats         Enable Stats
          --max-size      Max response image size (KB) (5120)
          --timeout       Upstream request timeout (4s)
          --no-follow     Disable following upstream redirects
          --listen        Address:Port to bind to for HTTP (0.0.0.0:8080)
          --ssl-listen    Address:Port to bind to for HTTPS/SSL/TLS
          --ssl-key       ssl private key (key.pem) path
          --ssl-cert      ssl cert (cert.pem) path
      -v, --verbose       Show verbose (debug) log level output
      -V, --version       print version and exit

    $ cat config.json
    {
        "HmacKey": "Some long string here...",
        "AllowList": []
    }

*   `HmacKey` is a secret key seed to the HMAC used for signing and
    validation.
*   `Allowlist` is a list of regex host matches to allow.

If an AllowList is defined, and a request does not match one of the listed host
regex, then the request is denied. Default is all requests pass the Allowlist
if none is specified.

Option flags, if provided, override those in the config file.

If stats flag is provided, then the service will track bytes and clients
served, and offer them up at an http endpoint `/status` via HTPT GET request.

## Additional tools

Go-Camo includes a couple of additional tools.

### url-tool

The `url-tool` utility provides a simple way to generate signed URLs from the command line.

    $ $GOPATH/bin/url-tool -h
    Usage:
      url-tool [OPTIONS]

    Help Options:
      -h, --help      Show this help message

    Application Options:
      -c, --config    JSON Config File
      -k, --key       HMAC key
      -e, --encode    Encode a url and print result
      -d, --decode    Decode a url and print result
          --prefix    Optional url prefix used by encode output

Example usage:

    $ $GOPATH/bin/url-tool -e -k "test" --prefix="https://img.example.org" "http://golang.org/doc/gopher/frontpage.png"
    https://img.example.org/0f6def1cb147b0e84f39cbddc5ea10c80253a6f3/687474703a2f2f676f6c616e672e6f72672f646f632f676f706865722f66726f6e74706167652e706e67 

Installation:

    $ go install github.com/cactus/go-camo/url-tool

### simple-server

The `simple-server` utility is useful for testing. It serves the contents of a
given directory over http. Nothing more.

    $ $GOPATH/bin/simple-server -h
    Usage of ./simple-server:
      -d=".": Directory to serve from

Installation:

    $ go install github.com/cactus/go-camo/simple-server

## Changelog

See `CHANGELOG.md`

## License

Released under the [MIT
license](http://www.opensource.org/licenses/mit-license.php). See `LICENSE.md`
file for details.

[1]: https://github.com/atmos/camo
[2]: http://code.google.com/p/rsc/source/browse/devweb
[3]: http://golang.org/doc/install
[4]: http://en.wikipedia.org/wiki/HMAC
[5]: http://cr.yp.to/daemontools.html
[6]: http://smarden.org/runit/
[7]: http://upstart.ubuntu.com/
[8]: http://launchd.macosforge.org/
[9]: http://cr.yp.to/daemontools/faq/create.html#why
