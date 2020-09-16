// =================================================================
//
// Work of the U.S. Department of Defense, Defense Digital Service.
// Released as open source under the MIT License.  See LICENSE file.
//
// =================================================================

package main

import (
	"archive/zip"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ocsp"

	"github.com/deptofdefense/iceberg/pkg/certs"
	"github.com/deptofdefense/iceberg/pkg/log"
	"github.com/deptofdefense/iceberg/pkg/ocsprenewer"
	"github.com/deptofdefense/iceberg/pkg/policy"
	"github.com/deptofdefense/iceberg/pkg/server"
)

const (
	IcebergVersion = "1.1.0"
)

const (
	TLSVersion1_0 = "1.0"
	TLSVersion1_1 = "1.1"
	TLSVersion1_2 = "1.2"
	TLSVersion1_3 = "1.3"
)

var (
	SupportedTLSVersions = []string{
		TLSVersion1_0,
		TLSVersion1_1,
		TLSVersion1_2,
		TLSVersion1_3,
	}
	TLSVersionIdentifiers = map[string]uint16{
		TLSVersion1_0: tls.VersionTLS10,
		TLSVersion1_1: tls.VersionTLS11,
		TLSVersion1_2: tls.VersionTLS12,
		TLSVersion1_3: tls.VersionTLS13,
	}
)

const (
	CurveP256 = "CurveP256"
	CurveP384 = "CurveP384"
	CurveP521 = "CurveP521"
	X25519    = "X25519"
)

const (
	BehaviorRedirect = "redirect"
	BehaviorNone     = "none"
)

var (
	Behaviors = []string{
		BehaviorRedirect,
		BehaviorNone,
	}
)

var (
	DefaultCurveIDs = []string{
		X25519,
		CurveP256,
		CurveP384,
		CurveP521,
	}
	SupportedCurveIDs = []string{
		CurveP256,
		CurveP384,
		CurveP521,
		X25519,
	}
	TLSCurveIdentifiers = map[string]tls.CurveID{
		CurveP256: tls.CurveP256,
		CurveP384: tls.CurveP384,
		CurveP521: tls.CurveP521,
		X25519:    tls.X25519,
	}
)

var (
	PEMCRLPrefix = []byte("-----BEGIN X509 CRL")
	PEMCRLType   = "X509 CRL"
)

func stringSliceContains(stringSlice []string, value string) bool {
	for _, x := range stringSlice {
		if value == x {
			return true
		}
	}
	return false
}

func stringSliceIndex(stringSlice []string, value string) int {
	for i, x := range stringSlice {
		if value == x {
			return i
		}
	}
	return -1
}

func merge(in ...map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	for _, m := range in {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

const (
	flagListenAddr     = "addr"
	flagRedirectAddr   = "redirect"
	flagPublicLocation = "public-location"
	//
	flagServerCert = "server-cert"
	flagServerKey  = "server-key"
	//
	flagClientCAFormat = "client-ca-format"
	flagClientCA       = "client-ca"
	//
	flagClientCRLFormat = "client-crl-format"
	flagClientCRL       = "client-crl"
	//
	flagOCSPServer        = "ocsp-server"
	flagOCSPRenewInterval = "ocsp-renew-interval"
	flagOCSPRefreshRatio  = "ocsp-refresh-ratio"
	flagOCSPRefreshMin    = "ocsp-refresh-min"
	flagOCSPHTTPTimeout   = "ocsp-http-timeout"
	//
	flagRootPath     = "root"
	flagTemplatePath = "template"
	//
	flagAccessPolicyFormat = "access-policy-format"
	flagAccessPolicyPath   = "access-policy"
	//
	flagTimeoutRead  = "timeout-read"
	flagTimeoutWrite = "timeout-write"
	flagTimeoutIdle  = "timeout-idle"
	//
	flagTLSMinVersion               = "tls-min-version"
	flagTLSMaxVersion               = "tls-max-version"
	flagTLSCipherSuites             = "tls-cipher-suites"
	flagTLSCurvePreferences         = "tls-curve-preferences"
	flagTLSPreferServerCipherSuites = "tls-prefer-server-cipher-suites"
	//
	flagBehaviorNotFound = "behavior-not-found"
	//
	flagLogPath = "log"
	//
	flagDryRun = "dry-run"
	//
	// Flags used by simulate request command
	//
	flagPath = "path"
	flagUser = "user"
)

type File struct {
	ModTime string
	Size    int64
	Type    string
	Path    string
}

func initFlags(flag *pflag.FlagSet) {
	flag.String(flagPublicLocation, "", "the public location of the server used for redirects")
	flag.StringP(flagListenAddr, "a", ":8080", "address that iceberg will listen on")
	flag.String(flagRedirectAddr, "", "address that iceberg will listen to and redirect requests to the public location")
	flag.String(flagServerCert, "", "path to server public cert")
	flag.String(flagServerKey, "", "path to server private key")
	flag.String(flagClientCAFormat, "pkcs7", "format of the CA bundle for client authentication, either pkcs7 or pem")
	flag.String(flagClientCA, "", "path to CA bundle for client authentication")
	flag.String(flagClientCRLFormat, "der", "format of the CRL bundle for client authentication, either der, der.zip, or pem")
	flag.String(flagClientCRL, "", "path to CRL bundle for client authentication")
	flag.StringP(flagRootPath, "r", "", "path to the document root served")
	flag.StringP(flagTemplatePath, "t", "", "path to the template file used during directory listing")
	flag.StringP(flagLogPath, "l", "-", "path to the log output.  Defaults to stdout.")
	flag.String(flagBehaviorNotFound, BehaviorNone, "default behavior when a file is not found.  One of: "+strings.Join(Behaviors, ","))
	initAccessPolicyFlags(flag)
	initTimeoutFlags(flag)
	initTLSFlags(flag)
	initOCSPFlags(flag)
	flag.Bool(flagDryRun, false, "exit after checking configuration")
}

func initSimulateRequestFlags(flag *pflag.FlagSet) {
	flag.String(flagPath, "", "path")
	flag.StringP(flagUser, "u", "", "user")
	initAccessPolicyFlags(flag)
}

func initTimeoutFlags(flag *pflag.FlagSet) {
	flag.String(flagTimeoutRead, "15m", "maximum duration for reading the entire request")
	flag.String(flagTimeoutWrite, "5m", "maximum duration before timing out writes of the response")
	flag.String(flagTimeoutIdle, "5m", "maximum amount of time to wait for the next request when keep-alives are enabled")
}

func initTLSFlags(flag *pflag.FlagSet) {
	flag.String(flagTLSMinVersion, TLSVersion1_0, "minimum TLS version accepted for requests")
	flag.String(flagTLSMaxVersion, TLSVersion1_3, "maximum TLS version accepted for requests")
	flag.String(flagTLSCipherSuites, "", "list of supported cipher suites for TLS versions up to 1.2 (TLS 1.3 is not configureable)")
	flag.String(flagTLSCurvePreferences, strings.Join(DefaultCurveIDs, ","), "curve preferences")
	flag.Bool(flagTLSPreferServerCipherSuites, false, "prefer server cipher suites")
}

func initOCSPFlags(flag *pflag.FlagSet) {
	flag.Bool(flagOCSPServer, false, "enable OCSP checking on the server certificate")
	flag.String(flagOCSPRenewInterval, "5m", "interval to run OCSP renewal")
	flag.Float64(flagOCSPRefreshRatio, 0.8, "the amount of time to wait for renewal between OCSP production and next update")
	flag.String(flagOCSPRefreshMin, "5m", "the minimum amount of time to wait before a refresh can occur")
	flag.String(flagOCSPHTTPTimeout, "30s", "the maximum amount of time before OCSP http requests timeout")
}

func initAccessPolicyFlags(flag *pflag.FlagSet) {
	flag.StringP(flagAccessPolicyFormat, "f", "json", "format of the policy file")
	flag.StringP(flagAccessPolicyPath, "p", "", "path to the policy file.")
}

func initViper(cmd *cobra.Command) (*viper.Viper, error) {
	v := viper.New()
	err := v.BindPFlags(cmd.Flags())
	if err != nil {
		return v, fmt.Errorf("error binding flag set to viper: %w", err)
	}
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv() // set environment variables to overwrite config
	return v, nil
}

func checkConfig(v *viper.Viper) error {
	addr := v.GetString(flagListenAddr)
	if len(addr) == 0 {
		return fmt.Errorf("listen address is missing")
	}
	redirectAddress := v.GetString(flagRedirectAddr)
	if len(redirectAddress) > 0 {
		publicLocation := v.GetString(flagPublicLocation)
		if len(publicLocation) == 0 {
			return fmt.Errorf("public location is required when redirecting")
		}
		if !strings.HasPrefix(publicLocation, "https://") {
			return fmt.Errorf("public location must start with \"https://\"")
		}
	}
	serverCert := v.GetString(flagServerCert)
	if len(serverCert) == 0 {
		return fmt.Errorf("server cert is missing")
	}
	serverKey := v.GetString(flagServerKey)
	if len(serverKey) == 0 {
		return fmt.Errorf("server key is missing")
	}
	clientCA := v.GetString(flagClientCA)
	if len(clientCA) == 0 {
		return fmt.Errorf("client CA is missing")
	}
	rootPath := v.GetString(flagRootPath)
	if len(rootPath) == 0 {
		return fmt.Errorf("root path is missing")
	}
	templatePath := v.GetString(flagTemplatePath)
	if len(templatePath) == 0 {
		return fmt.Errorf("template path is missing")
	}
	if err := checkAccessPolicyConfig(v); err != nil {
		return fmt.Errorf("invalid access policy configuration: %w", err)
	}
	logPath := v.GetString(flagLogPath)
	if len(logPath) == 0 {
		return fmt.Errorf("log path is missing")
	}
	timeoutRead := v.GetString(flagTimeoutRead)
	if len(timeoutRead) == 0 {
		return fmt.Errorf("read timeout is missing")
	}
	timeoutReadDuration, err := time.ParseDuration(timeoutRead)
	if err != nil {
		return fmt.Errorf("error parsing read timeout: %w", err)
	}
	if timeoutReadDuration < 5*time.Second || timeoutReadDuration > 30*time.Minute {
		return fmt.Errorf("invalid read timeout %q, must be greater than or equal to 5 seconds and less than or equal to 30 minutes", timeoutReadDuration)
	}
	timeoutWrite := v.GetString(flagTimeoutWrite)
	if len(timeoutWrite) == 0 {
		return fmt.Errorf("write timeout is missing")
	}
	timeoutWriteDuration, err := time.ParseDuration(timeoutWrite)
	if err != nil {
		return fmt.Errorf("error parsing write timeout: %w", err)
	}
	if timeoutWriteDuration < 5*time.Second || timeoutWriteDuration > 30*time.Minute {
		return fmt.Errorf("invalid write timeout %q, must be greater than or equal to 5 seconds and less than or equal to 30 minutes", timeoutWriteDuration)
	}
	timeoutIdle := v.GetString(flagTimeoutIdle)
	if len(timeoutIdle) == 0 {
		return fmt.Errorf("idle timeout is missing")
	}
	timeoutIdleDuration, err := time.ParseDuration(timeoutIdle)
	if err != nil {
		return fmt.Errorf("error parsing idle timeout: %w", err)
	}
	if timeoutIdleDuration < 5*time.Second || timeoutIdleDuration > 30*time.Minute {
		return fmt.Errorf("invalid idle timeout %q, must be greater than or equal to 5 seconds and less than or equal to 30 minutes", timeoutIdleDuration)
	}
	if err := checkTLSConfig(v, tls.CipherSuites()); err != nil {
		return fmt.Errorf("error with TLS configuration: %w", err)
	}
	if err := checkOCSPConfig(v); err != nil {
		return fmt.Errorf("errors with OCSP configuration: %w", err)
	}
	return nil
}

func checkSimulateRequestConfig(v *viper.Viper) error {
	path := v.GetString(flagPath)
	if len(path) == 0 {
		return fmt.Errorf("path is missing")
	}
	user := v.GetString(flagUser)
	if len(user) == 0 {
		return fmt.Errorf("user is missing")
	}
	if err := checkAccessPolicyConfig(v); err != nil {
		return err
	}
	return nil
}

func checkTLSConfig(v *viper.Viper, supportedCipherSuites []*tls.CipherSuite) error {
	minVersion := v.GetString(flagTLSMinVersion)
	minVersionIndex := stringSliceIndex(SupportedTLSVersions, minVersion)
	if minVersionIndex == -1 {
		return fmt.Errorf("invalid minimum TLS version %q", minVersion)
	}
	maxVersion := v.GetString(flagTLSMaxVersion)
	maxVersionIndex := stringSliceIndex(SupportedTLSVersions, maxVersion)
	if maxVersionIndex == -1 {
		return fmt.Errorf("invalid maximum TLS version %q", maxVersion)
	}
	if minVersionIndex > maxVersionIndex {
		return fmt.Errorf("invalid TLS versions, minium version %q is greater than maximum version %q", minVersion, maxVersion)
	}
	curvePreferencesString := v.GetString(flagTLSCurvePreferences)
	if len(curvePreferencesString) == 0 {
		return fmt.Errorf("TLS curve preferences are missing")
	}
	curvePreferences := strings.Split(curvePreferencesString, ",")
	for _, curveID := range curvePreferences {
		if !stringSliceContains(SupportedCurveIDs, curveID) {
			return fmt.Errorf("invalid curve preference %q", curveID)
		}
	}
	cipherSuitesString := v.GetString(flagTLSCipherSuites)
	if len(cipherSuitesString) > 0 {
		cipherSuitesMap := map[string]uint16{}
		for _, cipherSuite := range supportedCipherSuites {
			cipherSuitesMap[cipherSuite.Name] = cipherSuite.ID
		}
		cipherSuiteNames := strings.Split(cipherSuitesString, ",")
		for _, cipherSuiteName := range cipherSuiteNames {
			if _, ok := cipherSuitesMap[cipherSuiteName]; !ok {
				return fmt.Errorf("unknown TLS cipher suite %q", cipherSuiteName)
			}
		}
	}
	return nil
}

func checkOCSPConfig(v *viper.Viper) error {
	minRefreshRatio := 0.1
	maxRefreshRatio := 0.9
	if v.GetBool(flagOCSPServer) {
		minRenewInterval := 10 * time.Second
		maxRenewInterval := 1 * time.Hour
		if renewInterval := v.GetDuration(flagOCSPRenewInterval); minRenewInterval < renewInterval || renewInterval > maxRenewInterval {
			return fmt.Errorf("the OCSP renew interval must fall between %q and %q, %q was provided", minRenewInterval, maxRenewInterval, renewInterval)
		}

		if refreshRatio := v.GetFloat64(flagOCSPRefreshRatio); refreshRatio < minRefreshRatio || refreshRatio > maxRefreshRatio {
			return fmt.Errorf("refresh ratio must fall between %f and %f, %f was provided", minRefreshRatio, maxRefreshRatio, refreshRatio)
		}

		minRefreshMin := 1 * time.Minute
		maxRefreshMin := 24 * time.Hour
		if refreshMin := v.GetDuration(flagOCSPRefreshMin); refreshMin < minRefreshMin || refreshMin > maxRefreshMin {
			return fmt.Errorf("refresh minimum time must fall between %q and %q, %q was provided", minRefreshMin, maxRefreshMin, refreshMin)
		}

		minHTTPTimeout := 1 * time.Second
		maxHTTPTimeout := 60 * time.Second
		if httpTimeout := v.GetDuration(flagOCSPHTTPTimeout); minHTTPTimeout < httpTimeout || httpTimeout > maxHTTPTimeout {
			return fmt.Errorf("the OCSP http client timeout must fall between %q and %q, %q was provided", minHTTPTimeout, maxHTTPTimeout, httpTimeout)
		}
	}
	return nil
}

func checkAccessPolicyConfig(v *viper.Viper) error {
	acessPolicyFormat := v.GetString(flagAccessPolicyFormat)
	if len(acessPolicyFormat) == 0 {
		return fmt.Errorf("access policy format is missing")
	}
	acessPolicyPath := v.GetString(flagAccessPolicyPath)
	if len(acessPolicyPath) == 0 {
		return fmt.Errorf("access policy path is missing")
	}
	return nil
}

func loadTemplate(p string) (*template.Template, error) {
	b, err := ioutil.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("error loading template from file %q: %w", p, err)
	}
	funcs := template.FuncMap(map[string]interface{}{
		"prefix": func(prefix string, s string) bool {
			return strings.HasPrefix(s, prefix)
		},
		"suffix": func(suffix string, s string) bool {
			return strings.HasSuffix(s, suffix)
		},
	})
	t, err := template.New("main").Funcs(funcs).Parse(string(b))
	if err != nil {
		return nil, fmt.Errorf("error parsing template from file %q: %w", p, err)
	}
	return t, nil
}

func newTraceID() string {
	traceID, err := uuid.NewV4()
	if err != nil {
		return ""
	}
	return traceID.String()
}

func initLogger(path string) (*log.SimpleLogger, error) {

	if path == "-" {
		return log.NewSimpleLogger(os.Stdout), nil
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("error opening log file %q: %w", path, err)
	}

	return log.NewSimpleLogger(f), nil
}

func getTLSVersion(r *http.Request) string {
	for k, v := range TLSVersionIdentifiers {
		if v == r.TLS.Version {
			return k
		}
	}
	return ""
}

func getTLSCipherSuite(r *http.Request) string {
	return tls.CipherSuiteName(r.TLS.CipherSuite)
}

func parseSliceOfDERCRL(data [][]byte) (map[string][]pkix.RevokedCertificate, error) {
	m := map[string][]pkix.RevokedCertificate{}
	for _, der := range data {
		list, err := x509.ParseDERCRL(der)
		if err != nil {
			return nil, fmt.Errorf("error parsing DER encoded CRL: %w", err)
		}
		m[list.TBSCertList.Issuer.String()] = list.TBSCertList.RevokedCertificates
	}
	return m, nil
}

func initCertificateRevocationLists(p string, format string) (map[string][]pkix.RevokedCertificate, error) {
	if len(p) == 0 {
		return nil, nil
	}

	if format == "der.zip" {
		zr, err := zip.OpenReader(p)
		if err != nil {
			return nil, fmt.Errorf("error reading zip file %q: %w", p, err)
		}
		data := make([][]byte, 0)
		for _, f := range zr.File {
			fr, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("error reading file %q in zip file %q: %w", f.Name, p, err)
			}
			b, err := ioutil.ReadAll(fr)
			if err != nil {
				return nil, fmt.Errorf("error loading CRL from file %q: %w", p, err)
			}
			_ = fr.Close() // close file reader
			data = append(data, b)
		}
		_ = zr.Close() // close zip reader
		return parseSliceOfDERCRL(data)
	}

	b, err := ioutil.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("error loading CRL from file %q: %w", p, err)
	}

	if format == "pem" {
		if !bytes.HasPrefix(b, PEMCRLPrefix) {
			return nil, fmt.Errorf("error parsing CRL from file %q: CRL does not start with expected byte sequence %q", p, string(PEMCRLPrefix))
		}
		block, _ := pem.Decode(b)
		if block == nil || block.Type != PEMCRLType {
			return nil, fmt.Errorf("error parsing CRL from file %q: %w", p, err)
		}
		return parseSliceOfDERCRL([][]byte{block.Bytes})
	}

	if format == "der" {
		return parseSliceOfDERCRL([][]byte{b})
	}

	return nil, fmt.Errorf("error parsing CRL from file %q: unknown format %q", p, format)
}

func initTLSConfig(v *viper.Viper, serverKeyPair tls.Certificate, clientCAs *x509.CertPool, minVersion string, maxVersion string, cipherSuites []uint16, tlsPreferServerCipherSuites bool, renewer *ocsprenewer.OCSPRenewer, logger *log.SimpleLogger) *tls.Config {

	config := &tls.Config{
		Certificates:             []tls.Certificate{serverKeyPair},
		ClientAuth:               tls.RequireAnyClientCert,
		ClientCAs:                clientCAs,
		MinVersion:               TLSVersionIdentifiers[minVersion],
		MaxVersion:               TLSVersionIdentifiers[maxVersion],
		PreferServerCipherSuites: tlsPreferServerCipherSuites,
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert := serverKeyPair
			if v.GetBool(flagOCSPServer) {
				staple := renewer.GetStaple()
				if staple != nil {
					switch staple.Status {
					case ocsp.Good:
						cert.OCSPStaple = renewer.GetStapleRaw()
					case ocsp.Revoked:
						// See RFC 5280
						_ = logger.Log(fmt.Sprintf("OCSP Response Revoked for reason code %d", staple.RevocationReason))
					case ocsp.Unknown:
						_ = logger.Log("OCSP Response Unknown")
					}
				} else {
					_ = logger.Log("No OCSP Response Yet")
				}
			}
			return &cert, nil
		},
	}

	if len(cipherSuites) > 0 {
		config.CipherSuites = cipherSuites
	}

	if tlsCurvePreferencesString := v.GetString(flagTLSCurvePreferences); len(tlsCurvePreferencesString) > 0 {
		curvePreferences := make([]tls.CurveID, 0)
		for _, str := range strings.Split(tlsCurvePreferencesString, ",") {
			curvePreferences = append(curvePreferences, TLSCurveIdentifiers[str])
		}
		config.CurvePreferences = curvePreferences
	}
	return config
}

func initCipherSuites(cipherSuiteNamesString string, supportedCipherSuites []*tls.CipherSuite) ([]uint16, error) {
	if len(cipherSuiteNamesString) == 0 {
		return nil, nil
	}
	cipherSuiteNames := strings.SplitN(cipherSuiteNamesString, ",", -1)
	cipherSuitesMap := map[string]uint16{}
	for _, cipherSuite := range supportedCipherSuites {
		cipherSuitesMap[cipherSuite.Name] = cipherSuite.ID
	}
	cipherSuites := make([]uint16, 0, len(cipherSuiteNames))
	for _, cipherSuiteName := range cipherSuiteNames {
		cipherSuiteID, ok := cipherSuitesMap[cipherSuiteName]
		if !ok {
			return nil, fmt.Errorf("unknown TLS cipher suite %q", cipherSuiteName)
		}
		cipherSuites = append(cipherSuites, cipherSuiteID)
	}
	return cipherSuites, nil
}

func verifyPeerCertificates(peerCertificates []*x509.Certificate, clientCAs *x509.CertPool, crl map[string][]pkix.RevokedCertificate) ([][]*x509.Certificate, error) {
	intermediates := x509.NewCertPool()
	for _, c := range peerCertificates[1:] {
		intermediates.AddCert(c)
	}
	verifiedChains, err := peerCertificates[0].Verify(x509.VerifyOptions{
		Roots:         clientCAs,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return nil, fmt.Errorf("error verifying chains: %w", err)
	}
	if crl != nil {
		for _, verifiedChain := range verifiedChains {
			for _, c := range verifiedChain {
				set := make([]pkix.RelativeDistinguishedNameSET, 0)
				issuer := pkix.RDNSequence(set)
				_, err := asn1.Unmarshal(c.RawIssuer, &issuer)
				if err != nil {
					return nil, fmt.Errorf("error unmarshaling raw issuer: %w", err)
				}
				if revokedCertificates, ok := crl[issuer.String()]; ok {
					for _, r := range revokedCertificates {
						if c.SerialNumber.Cmp(r.SerialNumber) == 0 {
							return nil, fmt.Errorf("error verifying chains: certificate with serial number %s by issuer %q found in CRL", c.SerialNumber.String(), issuer.String())
						}
					}
				}
			}
		}
	}
	return verifiedChains, nil
}

func main() {

	rootCommand := &cobra.Command{
		Use:                   `iceberg [flags]`,
		DisableFlagsInUseLine: true,
		Short:                 "iceberg is a file server using client certificate authentication and policy-based access control.",
	}

	validateAccessPolicyCommand := &cobra.Command{
		Use:                   `validate-access-policy [--access-policy POLICY_FILE] [--access-policy-format POLICY_FORMAT]`,
		DisableFlagsInUseLine: true,
		Short:                 "validate the iceberg access policy file",
		SilenceErrors:         true,
		SilenceUsage:          true,
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := initViper(cmd)
			if err != nil {
				return fmt.Errorf("error initializing viper: %w", err)
			}

			if len(args) > 1 {
				return cmd.Usage()
			}

			if errConfig := checkAccessPolicyConfig(v); errConfig != nil {
				return errConfig
			}

			accessPolicyDocument, err := policy.ParseAccessPolicy(v.GetString(flagAccessPolicyPath), v.GetString(flagAccessPolicyFormat))
			if err != nil {
				return fmt.Errorf("error loading policy: %w", err)
			}

			err = accessPolicyDocument.Validate()
			if err != nil {
				return fmt.Errorf("error validating policy: %w", err)
			}

			return nil
		},
	}
	initFlags(validateAccessPolicyCommand.Flags())

	defaultsCommand := &cobra.Command{
		Use:                   `defaults`,
		DisableFlagsInUseLine: true,
		Short:                 "show defaults",
		SilenceErrors:         true,
		SilenceUsage:          true,
	}

	showDefaultTLSCipherSuites := &cobra.Command{
		Use:                   `tls-cipher-suites`,
		DisableFlagsInUseLine: true,
		Short:                 "show default TLS cipher suites",
		SilenceErrors:         true,
		SilenceUsage:          true,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := initViper(cmd)
			if err != nil {
				return fmt.Errorf("error initializing viper: %w", err)
			}
			if len(args) > 0 {
				return cmd.Usage()
			}
			supportedCipherSuites := tls.CipherSuites()
			names := make([]string, 0, len(supportedCipherSuites))
			for _, cipherSuite := range supportedCipherSuites {
				names = append(names, cipherSuite.Name)
			}
			fmt.Println(strings.Join(names, "\n"))
			return nil
		},
	}

	showDefaultTLSCurvePreferences := &cobra.Command{
		Use:                   `tls-curve-preferences`,
		DisableFlagsInUseLine: true,
		Short:                 "show default TLS curve preferences",
		SilenceErrors:         true,
		SilenceUsage:          true,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := initViper(cmd)
			if err != nil {
				return fmt.Errorf("error initializing viper: %w", err)
			}
			if len(args) > 0 {
				return cmd.Usage()
			}
			fmt.Println(strings.Join(DefaultCurveIDs, "\n"))
			return nil
		},
	}

	defaultsCommand.AddCommand(showDefaultTLSCipherSuites, showDefaultTLSCurvePreferences)

	serveCommand := &cobra.Command{
		Use:                   `serve [flags]`,
		DisableFlagsInUseLine: true,
		Short:                 "start the iceberg server",
		SilenceErrors:         true,
		SilenceUsage:          true,
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := initViper(cmd)
			if err != nil {
				return fmt.Errorf("error initializing viper: %w", err)
			}

			if len(args) > 1 {
				return cmd.Usage()
			}

			if errConfig := checkConfig(v); errConfig != nil {
				return errConfig
			}

			logger, err := initLogger(v.GetString(flagLogPath))
			if err != nil {
				return fmt.Errorf("error initializing logger: %w", err)
			}

			listenAddress := v.GetString(flagListenAddr)
			redirectAddress := v.GetString(flagRedirectAddr)
			publicLocation := v.GetString(flagPublicLocation)
			rootPath := v.GetString(flagRootPath)

			root := afero.NewBasePathFs(afero.NewReadOnlyFs(afero.NewOsFs()), rootPath)

			directoryListingTemplate, err := loadTemplate(v.GetString(flagTemplatePath))
			if err != nil {
				return fmt.Errorf("error loading directory listing template: %w", err)
			}

			accessPolicyDocument, err := policy.ParseAccessPolicy(v.GetString(flagAccessPolicyPath), v.GetString(flagAccessPolicyFormat))
			if err != nil {
				return fmt.Errorf("error loading policy: %w", err)
			}

			err = accessPolicyDocument.Validate()
			if err != nil {
				return fmt.Errorf("error validating policy: %w", err)
			}

			serverKeyPair, err := tls.LoadX509KeyPair(v.GetString(flagServerCert), v.GetString(flagServerKey))
			if err != nil {
				return fmt.Errorf("error loading server key pair: %w", err)
			}

			clientCAs, err := certs.LoadCertPool(v.GetString(flagClientCA), v.GetString(flagClientCAFormat))
			if err != nil {
				return fmt.Errorf("error loading client certificate authority: %w", err)
			}

			serverCert, errServerCert := certs.ParseCert(v.GetString(flagServerCert))
			if err != nil {
				return fmt.Errorf("unable to parse server certificate: %w", errServerCert)
			}

			// Only run OCSPRenewer if the flag is set and the OCSP server exists to make the request
			// Will also want a flag that controls this which takes precedence over the value on the cert
			var renewer *ocsprenewer.OCSPRenewer
			if v.GetBool(flagOCSPServer) && len(serverCert.OCSPServer) > 0 {

				issuerCert, errIssuerCert := certs.ParseCert(v.GetString(flagClientCA))
				if err != nil {
					return fmt.Errorf("unable to parse client CA certificate: %w", errIssuerCert)
				}

				httpClient := http.Client{Timeout: v.GetDuration(flagOCSPHTTPTimeout)}
				refreshRatio := v.GetFloat64(flagOCSPRefreshRatio)
				refreshMin := v.GetDuration(flagOCSPRefreshMin)
				renewer = ocsprenewer.New(serverCert, issuerCert, &httpClient, refreshRatio, refreshMin)
				go func() {
					// The tick time should likely be half the RefreshMin
					for ; true; <-time.Tick(v.GetDuration(flagOCSPRenewInterval)) {
						errRenew := renewer.Renew()
						// Log errors but don't break, this helps recover from OCSP service outages.
						if errRenew != nil {
							_ = logger.Log(fmt.Sprintf("OCSP renewal error: %v", errRenew))
						}
					}
				}()
			}

			tlsMinVersion := v.GetString(flagTLSMinVersion)

			tlsMaxVersion := v.GetString(flagTLSMaxVersion)

			tlsPreferServerCipherSuites := v.GetBool(flagTLSPreferServerCipherSuites)

			cipherSuiteNames := v.GetString(flagTLSCipherSuites)

			supportedCipherSuites := tls.CipherSuites()

			cipherSuites, err := initCipherSuites(cipherSuiteNames, supportedCipherSuites)
			if err != nil {
				return fmt.Errorf("error initializing cipher suites: %w", err)
			}

			crl, err := initCertificateRevocationLists(v.GetString(flagClientCRL), v.GetString(flagClientCRLFormat))
			if err != nil {
				return fmt.Errorf("error initializing certificate revocation lists: %w", err)
			}

			tlsConfig := initTLSConfig(v, serverKeyPair, clientCAs, tlsMinVersion, tlsMaxVersion, cipherSuites, tlsPreferServerCipherSuites, renewer, logger)

			redirectNotFound := v.GetString(flagBehaviorNotFound) == BehaviorRedirect

			httpsServer := &http.Server{
				Addr:         listenAddress,
				IdleTimeout:  v.GetDuration(flagTimeoutIdle),
				ReadTimeout:  v.GetDuration(flagTimeoutRead),
				WriteTimeout: v.GetDuration(flagTimeoutWrite),
				TLSConfig:    tlsConfig,
				ErrorLog:     log.WrapStandardLogger(logger),
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					//
					icebergTraceID := newTraceID()
					//
					fields := map[string]interface{}{
						"iceberg_trace_id": icebergTraceID,
						"url":              r.URL.String(),
					}
					//
					peerCertificates := r.TLS.PeerCertificates
					if len(peerCertificates) == 0 {
						_ = logger.Log("Missing client certificate", fields)
						http.Error(w, "Missing client certificate", http.StatusBadRequest)
						return
					}
					verifiedChains, err := verifyPeerCertificates(peerCertificates, clientCAs, crl)
					if err != nil {
						_ = logger.Log("Certificate denied", merge(fields, map[string]interface{}{
							"error":    err.Error(),
							"subjects": certs.Subjects(peerCertificates),
							"issuers":  certs.Issuers(peerCertificates),
						}))
						http.Error(w, "Could not verify client certificate", http.StatusForbidden)
						return
					} else {
						_ = logger.Log("Certificate verified", merge(fields, map[string]interface{}{
							"subjects": certs.Subjects(peerCertificates),
							"issuers":  certs.Issuers(peerCertificates),
						}))
					}
					//
					user := &policy.User{
						Subject: verifiedChains[0][0].Subject,
					}
					//
					_ = logger.Log("Request", merge(fields, map[string]interface{}{
						"user_dn":          user.DistinguishedName(),
						"source":           r.RemoteAddr,
						"referer":          r.Header.Get("referer"),
						"host":             r.Host,
						"method":           r.Method,
						"tls_version":      getTLSVersion(r),
						"tls_cipher_suite": getTLSCipherSuite(r),
					}))

					// Get path from URL
					p := server.TrimTrailingForwardSlash(server.CleanPath(r.URL.Path))

					qs := r.URL.Query()

					// If path is not clean
					if !server.CheckPath(p) {
						_ = logger.Log("Invalid path", merge(fields, map[string]interface{}{
							"user_dn": user.DistinguishedName(),
							"path":    p,
						}))
						http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
						return
					}

					if !accessPolicyDocument.Evaluate(p, user) {
						_ = logger.Log("Access denied", merge(fields, map[string]interface{}{
							"user_dn": user.DistinguishedName(),
						}))
						http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
						return
					} else {
						_ = logger.Log("Access allowed", merge(fields, map[string]interface{}{
							"user_dn": user.DistinguishedName(),
						}))
					}

					fi, err := root.Stat(p)
					if err != nil {
						if os.IsNotExist(err) {
							_ = logger.Log("Not found", merge(fields, map[string]interface{}{
								"path": p,
							}))
							if redirectNotFound {
								http.Redirect(w, r, publicLocation, http.StatusSeeOther)
								return
							}
							http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
							return
						}
						_ = logger.Log("Error stating file", merge(fields, map[string]interface{}{
							"path": p,
						}))
						http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
						return
					}
					if fi.IsDir() {
						indexPath := filepath.Join(p, "index.html")
						indexFileInfo, err := root.Stat(indexPath)
						if err != nil && !os.IsNotExist(err) {
							_ = logger.Log("Error stating index file", merge(fields, map[string]interface{}{
								"path": indexPath,
							}))
							http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
							return
						}
						if os.IsNotExist(err) || indexFileInfo.IsDir() {
							fileInfos, err := afero.ReadDir(root, p)
							if err != nil {
								_ = logger.Log("Error reading directory", merge(fields, map[string]interface{}{
									"path": p,
								}))
								http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
								return
							}
							//
							files := make([]File, 0, len(fileInfos))
							for _, fi := range fileInfos {
								fileType := "File"
								if fi.IsDir() {
									fileType = "Directory"
								}
								files = append(files, File{
									ModTime: fi.ModTime().In(time.UTC).Format(time.RFC3339),
									Size:    fi.Size(),
									Path:    filepath.Join(p, fi.Name()),
									Type:    fileType,
								})
							}
							// sort files
							sort.SliceStable(files, func(i, j int) bool {
								iType := files[i].Type
								jType := files[j].Type
								if iType != jType {
									if iType == "Directory" {
										return true
									}
									if jType == "Directory" {
										return false
									}
								}
								iStr := filepath.Base(files[i].Path)
								jStr := filepath.Base(files[j].Path)
								iValue, iErr := strconv.Atoi(iStr)
								jValue, jErr := strconv.Atoi(jStr)
								if iErr == nil && jErr == nil {
									return iValue < jValue
								}
								if iErr == nil {
									return true
								}
								if jErr == nil {
									return false
								}
								return strings.Compare(iStr, jStr) <= 0
							})
							//
							server.ServeTemplate(w, r, directoryListingTemplate, struct {
								Up        string
								Directory string
								Files     []File
							}{
								Up:        filepath.Dir(p),
								Directory: p,
								Files:     files,
							})
							return
						}
						server.ServeFile(w, r, root, indexPath, time.Time{}, false, nil)
						return
					}
					if d, ok := qs["download"]; ok && len(d) > 0 && (d[0] == "false" || d[0] == "0") {
						server.ServeFile(w, r, root, p, fi.ModTime(), false, nil)
					} else {
						server.ServeFile(w, r, root, p, fi.ModTime(), true, nil)
					}
				}),
			}
			// If dry run, then return before starting servers.
			if v.GetBool(flagDryRun) {
				return nil
			}
			//
			if len(redirectAddress) > 0 && len(publicLocation) > 0 {
				httpServer := &http.Server{
					Addr:     redirectAddress,
					ErrorLog: log.WrapStandardLogger(logger),
					Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						_ = logger.Log("Redirecting request", map[string]interface{}{
							"iceberg_trace_id": newTraceID(),
							"url":              r.URL.String(),
							"target":           publicLocation,
						})
						http.Redirect(w, r, publicLocation, http.StatusSeeOther)
					}),
				}
				_ = logger.Log("Redirecting http to https", map[string]interface{}{
					"source": redirectAddress,
					"target": publicLocation,
				})
				go func() { _ = httpServer.ListenAndServe() }()
			}
			//
			_ = logger.Log("Starting server", map[string]interface{}{
				"addr":                        listenAddress,
				"idleTimeout":                 httpsServer.IdleTimeout.String(),
				"readTimeout":                 httpsServer.ReadTimeout.String(),
				"writeTimeout":                httpsServer.WriteTimeout.String(),
				"tlsMinVersion":               tlsMinVersion,
				"tlsMaxVersion":               tlsMaxVersion,
				"tlsPreferServerCipherSuites": tlsPreferServerCipherSuites,
			})
			return httpsServer.ListenAndServeTLS("", "")
		},
	}
	initFlags(serveCommand.Flags())

	simulateCommand := &cobra.Command{
		Use:                   `simulate`,
		DisableFlagsInUseLine: true,
		Short:                 "simulate action",
		SilenceErrors:         true,
		SilenceUsage:          true,
	}

	simulateRequestCommand := &cobra.Command{
		Use:                   `request [--access-policy POLICY_FILE] [--access-policy-format POLICY_FORMAT] [--user USER] [--path PATH]`,
		DisableFlagsInUseLine: true,
		Short:                 "simulate a request",
		SilenceErrors:         true,
		SilenceUsage:          true,
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := initViper(cmd)
			if err != nil {
				return fmt.Errorf("error initializing viper: %w", err)
			}

			if len(args) > 1 {
				return cmd.Usage()
			}

			if errConfig := checkSimulateRequestConfig(v); errConfig != nil {
				return errConfig
			}

			accessPolicyDocument, err := policy.ParseAccessPolicy(v.GetString(flagAccessPolicyPath), v.GetString(flagAccessPolicyFormat))
			if err != nil {
				return fmt.Errorf("error loading policy: %w", err)
			}

			err = accessPolicyDocument.Validate()
			if err != nil {
				return fmt.Errorf("error validating policy: %w", err)
			}

			path := v.GetString(flagPath)

			user := policy.ParseUser(v.GetString(flagUser))

			ok := accessPolicyDocument.Evaluate(path, user)

			if ok {
				fmt.Println("allow")
			} else {
				fmt.Println("deny")
			}

			return nil
		},
	}
	initSimulateRequestFlags(simulateRequestCommand.Flags())

	simulateCommand.AddCommand(simulateRequestCommand)

	versionCommand := &cobra.Command{
		Use:                   `version`,
		DisableFlagsInUseLine: true,
		Short:                 "show version",
		SilenceErrors:         true,
		SilenceUsage:          true,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println(IcebergVersion)
			return nil
		},
	}

	rootCommand.AddCommand(validateAccessPolicyCommand, defaultsCommand, serveCommand, simulateCommand, versionCommand)

	if err := rootCommand.Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "iceberg: "+err.Error())
		_, _ = fmt.Fprintln(os.Stderr, "Try iceberg --help for more information.")
		os.Exit(1)
	}
}
