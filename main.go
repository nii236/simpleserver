package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

var unencryptedFlag = flag.Bool("unsafe", false, "Disable https")
var passwordFlag = flag.String("password", "", "Password to enable basic auth. Username is simpleserver.")
var portFlag = flag.String("port", "8888", "Port number to run server on.")

// From https://golang.org/src/net/http/server.go
// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func getExternalIP() string {
	resp, err := http.Get("http://ifconfig.co")
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	return buf.String()
}

// GenX509KeyPair generates the TLS keypair for the server
func GenX509KeyPair(ip string) (tls.Certificate, error) {
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.Unix()),
		Subject: pkix.Name{
			CommonName:   ip,
			Organization: []string{"nii corp"},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, 1), // Valid for one day
		SubjectKeyId:          []byte{113, 117, 105, 99, 107, 115, 101, 114, 118, 101},
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template,
		priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	var outCert tls.Certificate
	outCert.Certificate = append(outCert.Certificate, cert)
	outCert.PrivateKey = priv

	return outCert, nil
}

// Usage prints the usage string
func Usage() {
	l := log.New(os.Stderr, "", 0)
	l.Fatalf("Usage: %s <directory-to-serve>\n", os.Args[0])
}

// ListenAndServeTLSKeyPair start a server using in-memory TLS KeyPair
func ListenAndServeTLSKeyPair(addr string, cert tls.Certificate,
	handler http.Handler) error {

	if addr == "" {
		return errors.New("Invalid address string")
	}

	server := &http.Server{Addr: addr, Handler: handler}

	config := &tls.Config{}
	config.NextProtos = []string{"http/1.1"}
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0] = cert

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	tlsListener := tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)},
		config)

	return server.Serve(tlsListener)
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}

func main() {
	flag.Parse()
	port := *portFlag
	pw := *passwordFlag
	unsafe := *unencryptedFlag

	ip := strings.TrimRight(getExternalIP(), "\r\n")

	fs := http.FileServer(http.Dir("."))
	ss := SimpleServer(fs, pw)

	if pw != "" {
		log.Printf("Protected: %s", pw)
	}
	if !unsafe {
		mux := http.NewServeMux()
		cert, err := GenX509KeyPair(ip)
		if err != nil {
			log.Fatalln(err)
		}

		mux.Handle("/", ss)

		log.Printf("Serving: https://%s:%s", ip, port)
		log.Fatalln(ListenAndServeTLSKeyPair(fmt.Sprintf(":%s", port), cert, mux))
	} else {
		mux := http.NewServeMux()
		mux.Handle("/", ss)
		log.Printf("Serving :%s", port)
		log.Fatalln(http.ListenAndServe(fmt.Sprintf(":%s", port), mux))
	}
}

func SimpleServer(h http.Handler, pw string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)

		if pw != "" {
			_, password, authOK := r.BasicAuth()
			if authOK == false {
				http.Error(w, "Not authorized", 401)
				return
			}

			if password != pw {
				http.Error(w, "Not authorized", 401)
				return
			}
		}
		t := time.Now()
		log.Printf("[%s]: %s\n", r.RemoteAddr, r.URL)
		h.ServeHTTP(w, r)
		log.Println("Finished - ", r.URL, time.Since(t))
	})
}
