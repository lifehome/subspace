package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/pquerna/otp"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/gorilla/securecookie"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme/autocert"
)

var (
	// Flags
	cli = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// datadir
	datadir string

	// The version is set by the build command.
	version string

	// httpd
	httpAddr   string
	httpHost   string
	httpPrefix string

	// Insecure http cookies (only recommended for internal LANs/VPNs)
	httpInsecure bool

	// subdir
	subdir string
	backlink string

	// show version
	showVersion bool

	// show help
	showHelp bool

	// debug logging
	debug bool

	// Let's Encrypt
	letsencrypt bool

	// securetoken
	securetoken *securecookie.SecureCookie

	// logger
	logger = log.New()

	// config
	config *Config

	// mailer
	mailer = NewMailer()

	// SAML
	samlSP *samlsp.Middleware

	// Error page HTML
	errorPageHTML = `<html><head><title>Error</title></head><body text="orangered" bgcolor="black"><h1>An error has occurred</h1></body></html>`

	// theme
	semanticTheme string

	// Totp
	tempTotpKey *otp.Key
)

func init() {
	cli.StringVar(&datadir, "datadir", "/data", "data dir")
	cli.StringVar(&backlink, "backlink", "", "[deprecated] backlink (optional)")
	cli.StringVar(&subdir, "subdir", "", "[optional] URL path(without hostname) to subspace instance, without trailing slash")
	cli.StringVar(&httpHost, "http-host", "", "HTTP host")
	cli.StringVar(&httpAddr, "http-addr", ":80", "HTTP listen address")
	cli.BoolVar(&httpInsecure, "http-insecure", false, "enable sessions cookies for http (no https) not recommended")
	cli.BoolVar(&letsencrypt, "letsencrypt", true, "enable TLS using Let's Encrypt on port 443")
	cli.BoolVar(&showVersion, "version", false, "display version and exit")
	cli.BoolVar(&showHelp, "help", false, "display help and exit")
	cli.BoolVar(&debug, "debug", false, "debug mode")
	cli.StringVar(&semanticTheme, "theme", "green", "Semantic-ui theme to use")
}

func main() {
	var err error

	cli.Parse(os.Args[1:])
	usage := func(msg string) {
		if msg != "" {
			fmt.Fprintf(os.Stderr, "ERROR: %s\n", msg)
		}
		fmt.Fprintf(os.Stderr, "Usage: %s --http-host subspace.example.com\n\n", os.Args[0])
		cli.PrintDefaults()
	}

	if showHelp {
		usage("Help info")
		os.Exit(0)
	}

	if showVersion {
		fmt.Printf("Subspace %s\n", version)
		os.Exit(0)
	}

	// show warning message if deprecated flags are used
	if backlink != "" {
		subdir = backlink
		logger.Warnf("You are using a deprecated flag `backlink`, and it will be removed in a future release.\nPlease kindly change the flag to `subdir` to avoid your installation being broken in future updates.")
		
		// sleep for 10 seconds before continue initializing
		logger.Error("[WARNING] Deprecated flag `backlink` detected, giving a 90 seconds startup delay...")
		time.Sleep(90 * time.Second)
	}

	// http host
	if httpHost == "" {
		usage("--http-host flag is required")
		os.Exit(1)
	}

	// debug logging
	logger.Out = os.Stdout
	if debug {
		logger.SetLevel(log.DebugLevel)
	}
	logger.Debugf("debug logging is enabled")

	// http port
	httpIP, httpPort, err := net.SplitHostPort(httpAddr)
	if err != nil {
		usage("invalid --http-addr: " + err.Error())
	}

	// Clean datadir path.
	datadir = filepath.Clean(datadir)

	// config
	config, err = NewConfig("config.json")
	if err != nil {
		logger.Fatal(err)
	}

	// TOTP
	err = config.GenerateTOTP()
	if err != nil {
		logger.Fatal(err)
	}

	// Secure token
	securetoken = securecookie.New([]byte(config.FindInfo().HashKey), []byte(config.FindInfo().BlockKey))

	// Configure SAML if metadata is present.
	if len(config.FindInfo().SAML.IDPMetadata) > 0 {
		if err := configureSAML(); err != nil {
			logger.Warnf("configuring SAML failed: %s", err)
		}
	}

	//
	// Routes
	//
	r := &httprouter.Router{}

	r.GET(subdir, Log(WebHandler(rootIndexHandler, "index")))
	r.GET(subdir + "/", Log(WebHandler(indexHandler, "index")))
	r.GET(subdir + "/help", Log(WebHandler(helpHandler, "help")))
	r.GET(subdir + "/configure", Log(WebHandler(configureHandler, "configure")))
	r.POST(subdir + "/configure", Log(WebHandler(configureHandler, "configure")))

	// SAML
	r.GET(subdir + "/sso", Log(ssoHandler))
	r.GET(subdir + "/saml/metadata", Log(samlHandler))
	r.POST(subdir + "/saml/metadata", Log(samlHandler))
	r.GET(subdir + "/saml/acs", Log(samlHandler))
	r.POST(subdir + "/saml/acs", Log(samlHandler))

	r.GET(subdir + "/totp/image", Log(WebHandler(totpQRHandler, "totp/image")))
	r.GET(subdir + "/signin", Log(WebHandler(signinHandler, "signin")))
	r.GET(subdir + "/signout", Log(WebHandler(signoutHandler, "signout")))
	r.POST(subdir + "/signin", Log(WebHandler(signinHandler, "signin")))
	r.GET(subdir + "/forgot", Log(WebHandler(forgotHandler, "forgot")))
	r.POST(subdir + "/forgot", Log(WebHandler(forgotHandler, "forgot")))

	r.GET(subdir + "/settings", Log(WebHandler(settingsHandler, "settings")))
	r.POST(subdir + "/settings", Log(WebHandler(settingsHandler, "settings")))

	r.GET(subdir + "/user/edit/:user", Log(WebHandler(userEditHandler, "user/edit")))
	r.POST(subdir + "/user/edit", Log(WebHandler(userEditHandler, "user/edit")))
	r.GET(subdir + "/user/delete/:user", Log(WebHandler(userDeleteHandler, "user/delete")))
	r.POST(subdir + "/user/delete", Log(WebHandler(userDeleteHandler, "user/delete")))

	r.GET(subdir + "/profile/add", Log(WebHandler(profileAddHandler, "profile/add")))
	r.POST(subdir + "/profile/add", Log(WebHandler(profileAddHandler, "profile/add")))
	r.GET(subdir + "/profile/connect/:profile", Log(WebHandler(profileConnectHandler, "profile/connect")))
	r.GET(subdir + "/profile/delete/:profile", Log(WebHandler(profileDeleteHandler, "profile/delete")))
	r.POST(subdir + "/profile/delete", Log(WebHandler(profileDeleteHandler, "profile/delete")))
	r.GET(subdir + "/profile/config/wireguard/:profile", Log(WebHandler(wireguardConfigHandler, "profile/config/wireguard")))
	r.GET(subdir + "/profile/qrconfig/wireguard/:profile", Log(WebHandler(wireguardQRConfigHandler, "profile/qrconfig/wireguard")))
	r.GET(subdir + "/static/*path", staticHandler)

	//
	// Server
	//

	httpTimeout := 10 * time.Minute
	maxHeaderBytes := 10 * (1024 * 1024)

	// Plain text web server for use behind a reverse proxy.
	if !letsencrypt {
		httpd := &http.Server{
			Handler:        r,
			Addr:           net.JoinHostPort(httpIP, httpPort),
			WriteTimeout:   httpTimeout,
			ReadTimeout:    httpTimeout,
			MaxHeaderBytes: maxHeaderBytes,
		}
		hostport := net.JoinHostPort(httpHost, httpPort)
		if httpPort == "80" {
			hostport = httpHost
		}
		if len(httpIP) == 0 {
			hostport = "[::]:" + httpPort
		}
		logger.Infof("Subspace version: %s %s", version, &url.URL{
			Scheme: "http",
			Host:   hostport,
			Path:   subdir,
		})
		logger.Fatal(httpd.ListenAndServe())
	}

	// Let's Encrypt TLS mode

	// autocert
	certmanager := autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache(filepath.Join(datadir, "letsencrypt")),
		HostPolicy: func(_ context.Context, host string) error {
			host = strings.TrimPrefix(host, "www.")
			if host == httpHost {
				return nil
			}
			if host == config.FindInfo().Domain {
				return nil
			}
			return fmt.Errorf("autocert: host %q not permitted by HostPolicy", host)
		},
	}

	// http redirect to https and Let's Encrypt auth
	go func() {
		redir := httprouter.New()
		redir.GET(subdir + "/*path", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
			r.URL.Scheme = "https"
			r.URL.Host = httpHost
			http.Redirect(w, r, r.URL.String(), http.StatusFound)
		})

		httpd := &http.Server{
			Handler:        certmanager.HTTPHandler(redir),
			Addr:           net.JoinHostPort(httpIP, "80"),
			WriteTimeout:   httpTimeout,
			ReadTimeout:    httpTimeout,
			MaxHeaderBytes: maxHeaderBytes,
		}
		if err := httpd.ListenAndServe(); err != nil {
			logger.Fatalf("http server on port 80 failed: %s", err)
		}
	}()

	// TLS
	tlsConfig := tls.Config{
		GetCertificate:           certmanager.GetCertificate,
		NextProtos:               []string{"http/1.1"},
		Rand:                     rand.Reader,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,

			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// Override default for TLS.
	if httpPort == "80" {
		httpPort = "443"
		httpAddr = net.JoinHostPort(httpIP, httpPort)
	}

	httpsd := &http.Server{
		Handler:        r,
		Addr:           httpAddr,
		WriteTimeout:   httpTimeout,
		ReadTimeout:    httpTimeout,
		MaxHeaderBytes: maxHeaderBytes,
	}

	// Enable TCP keep alives on the TLS connection.
	tcpListener, err := net.Listen("tcp", httpAddr)
	if err != nil {
		logger.Fatalf("listen failed: %s", err)
		return
	}
	tlsListener := tls.NewListener(tcpKeepAliveListener{tcpListener.(*net.TCPListener)}, &tlsConfig)

	hostport := net.JoinHostPort(httpHost, httpPort)
	if httpPort == "443" {
		hostport = httpHost
	}
	if len(httpIP) == 0 {
		hostport = "[::]:" + httpPort
	}
	logger.Infof("Subspace version: %s %s", version, &url.URL{
		Scheme: "https",
		Host:   hostport,
		Path:   subdir,
	})
	logger.Fatal(httpsd.Serve(tlsListener))
}

type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (l tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := l.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(10 * time.Minute)
	return tc, nil
}

func configureSAML() error {
	info := config.FindInfo()

	if len(info.SAML.IDPMetadata) == 0 {
		return fmt.Errorf("no IDP metadata")
	}
	entity := &saml.EntityDescriptor{}
	err := xml.Unmarshal([]byte(info.SAML.IDPMetadata), entity)

	if err != nil && err.Error() == "expected element type <EntityDescriptor> but have <EntitiesDescriptor>" {
		entities := &saml.EntitiesDescriptor{}
		if err := xml.Unmarshal([]byte(info.SAML.IDPMetadata), entities); err != nil {
			return err
		}

		err = fmt.Errorf("no entity found with IDPSSODescriptor")
		for i, e := range entities.EntityDescriptors {
			if len(e.IDPSSODescriptors) > 0 {
				entity = &entities.EntityDescriptors[i]
				err = nil
			}
		}
	}
	if err != nil {
		return err
	}

	keyPair, err := tls.X509KeyPair(info.SAML.Certificate, info.SAML.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to load SAML keypair: %s", err)
	}

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse SAML certificate: %s", err)
	}

	rootURL := url.URL{
		Scheme: "https",
		Host:   httpHost,
		Path:   subdir,
	}

	if httpInsecure {
		rootURL.Scheme = "http"
	}

	newsp, err := samlsp.New(samlsp.Options{
		URL:               rootURL,
		Key:               keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:       keyPair.Leaf,
		IDPMetadata:       entity,
		CookieName:        SessionCookieNameSSO,
		CookieDomain:      httpHost, // TODO: this will break if using a custom domain.
		CookieSecure:      !httpInsecure,
		Logger:            logger,
		AllowIDPInitiated: true,
	})
	if err != nil {
		logger.Warnf("failed to configure SAML: %s", err)
		samlSP = nil
		return fmt.Errorf("failed to configure SAML: %s", err)
	}

	newsp.ServiceProvider.AuthnNameIDFormat = saml.EmailAddressNameIDFormat

	samlSP = newsp
	logger.Infof("successfully configured SAML")
	return nil
}
