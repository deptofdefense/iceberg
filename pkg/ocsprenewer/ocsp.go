// =================================================================
//
// Work of the U.S. Department of Defense, Defense Digital Service.
// Released as open source under the MIT License.  See LICENSE file.
//
// =================================================================

package ocsprenewer

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

// OCSPRenewer is the configuration for getting the Staple
type OCSPRenewer struct {
	sync.Mutex

	Certificate, Issuer *x509.Certificate // the certificates for the OCSP Request
	HTTPClient          *http.Client      // the http client to use
	RefreshRatio        float64           // the percentage of time to wait between ThisUpdate and NextUpdate before renewing
	RefreshMin          time.Duration     // the minimum time that must elapse before a new OCSP request is issued

	raw    []byte         // the raw response from the OCSP responder
	staple *ocsp.Response // the parsed response from the OCSP responder
}

// GetStaple returns the OCSP Response
func (renewer *OCSPRenewer) GetStaple() *ocsp.Response {
	renewer.Lock()
	defer renewer.Unlock()
	return renewer.staple
}

// GetStapleRaw returns the raw OCSP Response
func (renewer *OCSPRenewer) GetStapleRaw() []byte {
	renewer.Lock()
	defer renewer.Unlock()
	return renewer.raw
}

func (renewer *OCSPRenewer) GetServers() []string {
	if renewer.Certificate == nil {
		return []string{}
	}
	return renewer.Certificate.OCSPServer
}

func (renewer *OCSPRenewer) GetFirstServer() string {
	if renewer.Certificate == nil || renewer.Certificate.OCSPServer == nil || len(renewer.Certificate.OCSPServer) == 0 {
		return ""
	}
	return renewer.Certificate.OCSPServer[0]
}

// ShouldRenew indicates if the OCSP Staple should be renewed
func (renewer *OCSPRenewer) ShouldRenew() bool {

	if renewer.staple != nil {

		// Do not renew if certificate has been revoked
		if !renewer.staple.RevokedAt.IsZero() {
			return false
		}

		now := time.Now()
		if renewer.staple.NextUpdate.IsZero() {
			// Staple missing expiration time, should renew after a waiting period.
			// This can happen if the OCSP responder isn't configured to provide when fresh revocation information is available.
			// In the case that nextUpdate isn't set the assumption is a renewal can always happen anytime.
			// Avoid overwhelming the server by waiting a while before requesting again.
			return now.After(renewer.staple.ThisUpdate.Add(renewer.RefreshMin))
		}
		if now.After(renewer.staple.NextUpdate) {
			// Staple expired, should renew
			return true
		}
		if renewer.staple.ProducedAt.IsZero() {
			// Staple missing initial validity time, should renew
			return true
		}

		// Should establish a window during which renew should start
		minUntilRefresh := time.Duration(float64(renewer.staple.NextUpdate.Sub(renewer.staple.ProducedAt)) * renewer.RefreshRatio)
		// Always wait a minimum amount of time before refresh
		if minUntilRefresh < renewer.RefreshMin {
			minUntilRefresh = renewer.RefreshMin
		}
		retryTime := renewer.staple.ProducedAt.Add(minUntilRefresh)

		return now.After(retryTime)
	}

	return true
}

// Renew does the work to renew an OCSP Staple
func (renewer *OCSPRenewer) Renew() error {

	// Renew should only happen once at a time
	renewer.Lock()
	defer renewer.Unlock()

	// Determine if now is the time to renew
	if !renewer.ShouldRenew() {
		return nil
	}

	if renewer.staple != nil {
		if renewer.staple.Status == ocsp.Revoked {
			return errors.New("certificate has been revoked")
		}
	}

	ocspReq, err := ocsp.CreateRequest(renewer.Certificate, renewer.Issuer, nil)
	if err != nil {
		return fmt.Errorf("error creating OCSP request: %w", err)
	}

	req, err := http.NewRequest(
		http.MethodPost,
		renewer.Certificate.OCSPServer[0],
		bytes.NewReader(ocspReq))
	if err != nil {
		return fmt.Errorf("error creating HTTP request: %w", err)
	}

	req.Header.Set("User-Agent", "ocsp")
	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Accept", "*/*")

	resp, err := renewer.HTTPClient.Do(req)
	if resp != nil {
		defer func() {
			errRespClose := resp.Body.Close()
			if errRespClose != nil {
				fmt.Printf("unable to close http body: %s\n", errRespClose)
			}
		}()
	}
	// If there's an HTTP error then set up a backoff to retry until success
	if err != nil {
		return fmt.Errorf("error making OCSP request: %w", err)
	}

	raw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading OCSP response: %w", err)
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
		return fmt.Errorf("error parsing OCSP response for certificate: %w", err)
	}

	if ocspResp == nil {
		return errors.New("no OCSP Response")
	}

	renewer.raw = raw // set raw to the raw response from the OCSP responder

	renewer.staple = ocspResp // set staple to the parsed response from the OCSP responder

	return nil
}

// New returns a new OCSPRenewer
func New(cert, issuer *x509.Certificate, httpClient *http.Client, refreshRatio float64, refreshMin time.Duration) *OCSPRenewer {
	return &OCSPRenewer{
		Certificate:  cert,
		Issuer:       issuer,
		HTTPClient:   httpClient,
		RefreshRatio: refreshRatio,
		RefreshMin:   refreshMin,
	}
}
