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

// OCSPRenewer is the configuration for getting the Staple
type OCSPRenewer struct {
	Certificate, Issuer *x509.Certificate // the certificates for the OCSP Request
	HTTPClient          *http.Client      // the http client to use
	Staple              *ocsp.Response    // the response from the OCSP Responder
	RefreshRatio        float64           // the percentage of time to wait between ThisUpdate and NextUpdate before renewing
	RefreshMin          time.Duration     // the minimum time that must elapse before a new OCSP request is issued
}

// GetStaple returns the OCSP Response
func (renewer *OCSPRenewer) GetStaple() *ocsp.Response {
	return renewer.Staple
}

// ShouldRenew indicates if the OCSP Staple should be renewed
func (renewer *OCSPRenewer) ShouldRenew() bool {

	if renewer.Staple != nil {
		// ThisUpdate: latest time known to have been good
		// ProducedAt: response generated
		// NextUpdate: expiration
		// RevokedAt: revocation time
		// fmt.Printf("ThisUpdate: [%s]\tProducedAt: [%s]\tNextUpdate: [%s]\tRevokedAt: [%s]\n",
		// 	renewer.Staple.ThisUpdate,
		// 	renewer.Staple.ProducedAt,
		// 	renewer.Staple.NextUpdate,
		// 	renewer.Staple.RevokedAt)

		// Do not renew if certificate has been revoked
		if !renewer.Staple.RevokedAt.IsZero() {
			return false
		}

		now := time.Now()
		if renewer.Staple.NextUpdate.IsZero() {
			// Staple missing expiration time, should renew after a waiting period.
			// This can happen if the OCSP responder isn't configured to provide when fresh revocation information is available.
			// In the case that nextUpdate isn't set the assumption is a renewal can always happen anytime.
			// Avoid overwhelming the server by waiting a while before requesting again.
			return now.After(renewer.Staple.ThisUpdate.Add(renewer.RefreshMin))
		}
		if now.After(renewer.Staple.NextUpdate) {
			// Staple expired, should renew
			return true
		}
		if renewer.Staple.ProducedAt.IsZero() {
			// Staple missing initial validity time, should renew
			return true
		}

		// Should establish a window during which renew should start
		minUntilRefresh := time.Duration(float64(renewer.Staple.NextUpdate.Sub(renewer.Staple.ProducedAt)) * renewer.RefreshRatio)
		// Always wait a minimum amount of time before refresh
		if minUntilRefresh < renewer.RefreshMin {
			minUntilRefresh = renewer.RefreshMin
		}
		retryTime := renewer.Staple.ProducedAt.Add(minUntilRefresh)

		return now.After(retryTime)
	}

	return true
}

// Renew does the work to renew an OCSP Staple
func (renewer *OCSPRenewer) Renew() error {

	// Determine if now is the time to renew
	if !renewer.ShouldRenew() {
		return nil
	}

	if renewer.Staple != nil {
		if renewer.Staple.Status == ocsp.Revoked {
			return errors.New("certificate has been revoked")
		}
	}

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
	resp, err := renewer.HTTPClient.Do(req)
	if resp != nil {
		defer func() {
			errRespClose := resp.Body.Close()
			if errRespClose != nil {
				fmt.Printf("unable to close http body: %s", errRespClose)
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
			// https://tools.ietf.org/html/rfc6960#section-4.2.1
			fmt.Printf("Response error: %s", re.Status.String())
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
	// Will also want a flag that controls this which takes precedence over the value on the cert
	var renewer *OCSPRenewer
	if len(cert.OCSPServer) > 0 {

		renewer = &OCSPRenewer{
			Certificate:  cert,
			Issuer:       issuer,
			HTTPClient:   http.DefaultClient,
			RefreshRatio: 0.8,
			RefreshMin:   5 * time.Minute,
		}
		go func() {
			// The tick time should likely be half the RefreshMin
			for ; true; <-time.Tick(10 * time.Second) {
				err := renewer.Renew()
				// Record errors but don't break, this helps recover from server outages.
				if err != nil {
					fmt.Println(err)
				}
			}
		}()

	}

	// Example of how to view the OCSP Status on the cert
	if renewer != nil {
		for {
			s := renewer.GetStaple()
			if s != nil {
				switch s.Status {
				case ocsp.Good:
					fmt.Printf("Good: %d\n", s.Status)
				case ocsp.Revoked:
					// See RFC 5280
					fmt.Printf("Revoked: %d, Reason: %d\n", s.Status, s.RevocationReason)
				case ocsp.Unknown:
					fmt.Printf("Unknown: %d\n", s.Status)
				}
			} else {
				fmt.Println("No OCSP Response Yet")
			}
			// Mimic an http request from a client that happens every 5 seconds
			time.Sleep(5 * time.Second)
		}
	}
}
