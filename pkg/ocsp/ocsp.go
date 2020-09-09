package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"

	"golang.org/x/crypto/ocsp"
)

func parseCert(filename string) (*x509.Certificate, error) {
	r, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(r)
	cert, err := x509.ParseCertificate(block.Bytes)
	return cert, err
}

func main() {

	certDir := "./temp/"

	cert, err := parseCert(path.Join(certDir, "client.crt"))
	if err != nil {
		panic(err)
	}

	issuer, err := parseCert(path.Join(certDir, "ca.crt"))
	if err != nil {
		panic(err)
	}

	if len(cert.OCSPServer) == 0 {
		panic(errors.New("No OCSP Server listed for cert"))
	}

	ocspReq, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		panic(err)
	}

	req, err := http.NewRequest(
		http.MethodPost,
		cert.OCSPServer[0],
		bytes.NewReader(ocspReq))
	if err != nil {
		panic(err)
	}

	req.Header.Set("User-Agent", "test")
	resp, err := http.DefaultClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		panic(err)
	}

	raw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	if resp.StatusCode != http.StatusOK {
		panic(errors.New(fmt.Sprintf("Bad response %s from %q: %q", resp.StatusCode, cert.OCSPServer[0], raw)))
	}

	ocspResp, err := ocsp.ParseResponseForCert(raw, cert, issuer)
	if err != nil {
		if re, ok := err.(ocsp.ResponseError); ok {
			switch re.Status {
			case ocsp.Success:
				fmt.Println("Success")
			case ocsp.TryLater:
				fmt.Println("Try Later")
			default:
				// Do nothing

			}
		}
		panic(err)
	}
	if ocspResp == nil {
		panic(errors.New("No OCSP Response"))
	}

	switch ocspResp.Status {
	case ocsp.Good:
		fmt.Println("Good")
	case ocsp.Revoked:
		fmt.Println("Revoked")
	case ocsp.Unknown:
		fmt.Println("Unknown")
	case ocsp.ServerFailed:
		fmt.Println("ServerFailed")
	default:
		panic(errors.New("OCSP status not specified"))
	}

	fmt.Println("\nStats:")
	fmt.Printf("ProducedAt: %q\n", ocspResp.ProducedAt)
	fmt.Printf("ThisUpdate: %q\n", ocspResp.ThisUpdate)
	fmt.Printf("Nextupdate: %q\n", ocspResp.NextUpdate)
	fmt.Printf("RevokedAt:  %q\n", ocspResp.RevokedAt)
}
