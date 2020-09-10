package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"time"

	"golang.org/x/crypto/ocsp"
)

func (renewer *OCSPRenewer) Renew() error {

	// TODO: Need to check if renewal can wait before making a request

	ocspReq, err := ocsp.CreateRequest(renewer.Certificate, renewer.Issuer, nil)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		renewer.Certificate.OCSPServer[0],
		bytes.NewReader(ocspReq))
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", "ocsp")
	resp, err := http.DefaultClient.Do(req)
	if resp != nil {
		defer func() {
			errRespClose := resp.Body.Close()
			if errRespClose != nil {
				fmt.Println(errRespClose)
				os.Exit(1)
			}
		}()
	}
	// If there's an HTTP error then set up a backoff to retry until success
	if err != nil {
		return err
	}

	raw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad response %d from %q: %q", resp.StatusCode, renewer.Certificate.OCSPServer[0], raw)
	}

	ocspResp, err := ocsp.ParseResponseForCert(raw, renewer.Certificate, renewer.Issuer)
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
		return err
	}
	if ocspResp == nil {
		return errors.New("no OCSP Response")
	}

	renewer.Staple = ocspResp

	return nil
}

func parseCert(filename string) (*x509.Certificate, error) {
	r, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(r)
	cert, err := x509.ParseCertificate(block.Bytes)
	return cert, err
}

type OCSPRenewer struct {
	Certificate, Issuer *x509.Certificate

	Staple *ocsp.Response
}

func (s *OCSPRenewer) GetStaple() (*ocsp.Response, error) {
	return s.Staple, nil
}

func main() {

	certDir := "./temp/"

	cert, err := parseCert(path.Join(certDir, "client.crt"))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	issuer, err := parseCert(path.Join(certDir, "ca.crt"))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Only do OCSPRenewer if the server exists to make the request
	if len(cert.OCSPServer) > 0 {
		renewer := OCSPRenewer{
			Certificate: cert,
			Issuer:      issuer,
		}
		go func() {
			for ; true; <-time.Tick(10 * time.Second) {
				err := renewer.Renew()
				if err != nil {
					fmt.Println(err)
				}
			}
		}()

		// View the OCSP Status on the cert
		for {
			s, err := renewer.GetStaple()
			if err != nil {
				os.Exit(1)
			}
			if s != nil {
				fmt.Println(s.Status)
			} else {
				fmt.Println("No OCSP Response Yet")
			}
			time.Sleep(5 * time.Second)
		}
	}

}
