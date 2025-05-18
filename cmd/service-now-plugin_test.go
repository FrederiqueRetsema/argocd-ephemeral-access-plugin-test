package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	argocd "github.com/argoproj-labs/argocd-ephemeral-access/api/argoproj/v1alpha1"
	api "github.com/argoproj-labs/argocd-ephemeral-access/api/ephemeral-access/v1alpha1"
	"github.com/argoproj-labs/argocd-ephemeral-access/pkg/plugin"

	coreV1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	testclient "k8s.io/client-go/kubernetes/fake"
)

type HelperMethodsTestSuite struct {
	suite.Suite
}

type K8SRelatedTestSuite struct {
	suite.Suite
}

type PluginHelperMethodsTestSuite struct {
	suite.Suite
}

type PublicMethodsTestSuite struct {
	suite.Suite
}

type SNOWTestSuite struct {
	suite.Suite
}

type CITestSuite struct {
	suite.Suite
}

type ChangeTestSuite struct {
	suite.Suite
}

type CheckCITestSuite struct {
	suite.Suite
}

type CheckChangeTestSuite struct {
	suite.Suite
}

type MockedLogger struct {
	mock.Mock
}

func (m *MockedLogger) Log(level hclog.Level, s string, args ...interface{}) {
	m.Called(s)
}

func (m *MockedLogger) Trace(s string, i ...interface{}) {
	m.Called(s)
}

func (m *MockedLogger) Debug(s string, i ...interface{}) {
	m.Called(s)
}

func (m *MockedLogger) Info(s string, i ...interface{}) {
	m.Called(s)
}

func (m *MockedLogger) Warn(s string, i ...interface{}) {
	m.Called(s)
}

func (m *MockedLogger) Error(s string, i ...interface{}) {
	m.Called(s)
}

func (m *MockedLogger) IsTrace() bool {
	m.Called()
	return false
}

func (m *MockedLogger) IsDebug() bool {
	m.Called()
	return true
}

func (m *MockedLogger) IsInfo() bool {
	m.Called()
	return true
}

func (m *MockedLogger) IsWarn() bool {
	m.Called()
	return true
}

func (m *MockedLogger) IsError() bool {
	m.Called()
	return true
}

func (m *MockedLogger) ImpliedArgs() []interface{} {
	m.Called()
	return nil
}

func (m *MockedLogger) With(args ...interface{}) hclog.Logger {
	m.Called()
	return nil
}

func (m *MockedLogger) Name() string {
	m.Called()
	return "myLogger"
}

func (m *MockedLogger) Named(s string) hclog.Logger {
	m.Called(s)
	return nil
}

func (m *MockedLogger) ResetNamed(s string) hclog.Logger {
	m.Called(s)
	return nil
}

func (m *MockedLogger) SetLevel(level hclog.Level) {
	m.Called(level)
}

func (m *MockedLogger) GetLevel() hclog.Level {
	m.Called()
	return hclog.Level(hclog.Debug)
}

func (m *MockedLogger) StandardLogger(opts *hclog.StandardLoggerOptions) *log.Logger {
	m.Called(opts)
	return nil
}

func (m *MockedLogger) StandardWriter(opts *hclog.StandardLoggerOptions) io.Writer {
	m.Called(opts)
	return nil
}

func testGetPlugin() (*ServiceNowPlugin, *MockedLogger) {
	loggerObj := new(MockedLogger)

	p := &ServiceNowPlugin{
		Logger: loggerObj,
	}

	return p, loggerObj
}

func (s *HelperMethodsTestSuite) TestGetEnvVarWithPanicNoEnvVar() {
	t := s.T()

	p, loggerObj := testGetPlugin()
	errorText := "Panic!"

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			s.Assertions.Equal(errorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	snowUrl = ""
	os.Setenv("SERVICE_NOW_URL", "")
	loggerObj.On("Error", errorText)

	snowUrl = p.getEnvVarWithPanic("SERVICE_NOW_URL", errorText)

	t.Errorf("The code did not panic")
}

func (s *HelperMethodsTestSuite) TestGetEnvVarWithPanicWithEnvVar() {
	t := s.T()

	p, loggerObj := testGetPlugin()

	snowUrl = ""
	os.Setenv("SERVICE_NOW_URL", "https://example.com")

	snowUrl = p.getEnvVarWithPanic("SERVICE_NOW_URL", "Panic!")

	s.Assertions.Equal("https://example.com", snowUrl, "The correct URL is retrieved")
	loggerObj.AssertExpectations(t)
}

func (s *HelperMethodsTestSuite) TestGetEnvVarWithDefaultNoEnvVar() {
	t := s.T()

	p, loggerObj := testGetPlugin()

	os.Setenv("TIMEZONE", "")
	loggerObj.On("Debug", "Environment variable TIMEZONE is empty, assuming UTC")

	timezone := p.getEnvVarWithDefault("TIMEZONE", "UTC")

	s.Assertions.Equal("UTC", timezone, "Assumed UTC correctly")
	loggerObj.AssertExpectations(t)
}

func (s *HelperMethodsTestSuite) TestGetEnvVarWithDefaultWithEnvVar() {
	t := s.T()

	p, loggerObj := testGetPlugin()
	os.Setenv("TIMEZONE", "Amsterdam/Europe")

	timezone := p.getEnvVarWithDefault("TIMEZONE", "UTC")

	s.Assertions.Equal("Amsterdam/Europe", timezone, "Environment TIMEZONE was filled, Retrieved Amsterdam/Europe correctly")
	loggerObj.AssertExpectations(t)
}

func (s *HelperMethodsTestSuite) TestGetLocalTime() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	time.Local = time.UTC
	currentTime := time.Now()
	timezone = "Europe/Amsterdam"
	currentTimeAmsterdamSummertime := time.Now().Add(2 * time.Hour)
	currentTimeAmsterdamWintertime := time.Now().Add(1 * time.Hour)

	currentTimeAmsterdamSummertimeString := fmt.Sprintf("%02d:%02d:%02d",
		currentTimeAmsterdamSummertime.Hour(),
		currentTimeAmsterdamSummertime.Minute(),
		currentTimeAmsterdamSummertime.Second())
	currentTimeAmsterdamWintertimeString := fmt.Sprintf("%02d:%02d:%02d",
		currentTimeAmsterdamWintertime.Hour(),
		currentTimeAmsterdamWintertime.Minute(),
		currentTimeAmsterdamWintertime.Second())

	currentTimeString := p.getLocalTime(currentTime)

	if currentTimeString != currentTimeAmsterdamSummertimeString &&
		currentTimeString != currentTimeAmsterdamWintertimeString {
		t.Errorf("Error: %s is not equal to Amsterdam Summertime (%s) or Amsterdam Wintertime (%s)",
			currentTimeString,
			currentTimeAmsterdamSummertimeString,
			currentTimeAmsterdamWintertimeString)
	}

	loggerObj.AssertExpectations(t)
}

func (s *HelperMethodsTestSuite) TestConvertTimeCorrectTime() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	result := p.convertTime("2025-05-15 18:14:13")
	assert.Equal(t, 18, result.Hour(), "Hours match")
	assert.Equal(t, 14, result.Minute(), "Minutes match")
	assert.Equal(t, 13, result.Second(), "Seconds match")

	loggerObj.AssertExpectations(t)
}

func (s *HelperMethodsTestSuite) TestConvertTimeIncorrectTime() {
	t := s.T()
	p, loggerObj := testGetPlugin()
	timeString := "current"

	errorText := fmt.Sprintf("Error in converting %s to go Time: parsing time \"currentZ\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \"currentZ\" as \"2006\"", timeString)
	loggerObj.On("Error", errorText)

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			s.Assertions.Equal(errorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	_ = p.convertTime(timeString)
}

func TestHelperMethods(t *testing.T) {
	suite.Run(t, new(HelperMethodsTestSuite))
}

func (s *K8SRelatedTestSuite) TestGetK8sConfig() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	// Will always panic because the tests are not run from within a Kubernetes cluster
	// Running this correctly, not just some environment variables must be set, but also a directory structure
	// for retrieving the token
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
		}
		loggerObj.AssertExpectations(t)
	}()

	unittest = false

	os.Setenv("KUBERNETES_SERVICE_HOST", "https://kubernetes.example.com")
	os.Setenv("KUBERNETES_SERVICE_PORT", "6443")

	p.getK8sConfig()

	t.Errorf("The code did not panic")
}

func (s *K8SRelatedTestSuite) TestGetCredentialsFromSecret() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	secretName := "generic-secret"
	namespace := "generic-namespace"
	genericUsername := "GenericUsername"
	genericPassword := "GenericPassword"

	setCredentialsSecret(namespace, secretName, genericUsername, genericPassword)

	loggerObj.On("Debug", fmt.Sprintf("Get credentials from secret [%s]%s...", namespace, secretName))

	username, password := p.getCredentialsFromSecret(namespace, secretName, "username", "password")

	s.Assertions.Equal(genericUsername, username, "Username found")
	s.Assertions.Equal(genericPassword, password, "Password found")
	loggerObj.AssertExpectations(t)
}

func (s *K8SRelatedTestSuite) TestGetCredentialsFromSecretSecretDoesntExist() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			s.Assertions.Equal("secrets \"does-not-exist\" not found", fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	secretName := "generic-secret"
	namespace := "generic-namespace"
	genericUsername := "GenericUsername"
	genericPassword := "GenericPassword"

	setCredentialsSecret(namespace, secretName, genericUsername, genericPassword)

	secretName = "does-not-exist"
	loggerObj.On("Debug", fmt.Sprintf("Get credentials from secret [%s]%s...", namespace, secretName))
	loggerObj.On("Error", fmt.Sprintf("Error getting secret %s, does secret exist in namespace %s?", secretName, namespace))

	_, _ = p.getCredentialsFromSecret(namespace, secretName, "username", "password")

}

func (s *K8SRelatedTestSuite) TestGetCINameEmpty() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	var app *argocd.Application = new(argocd.Application)
	var m map[string]string

	loggerObj.On("Debug", "Search for ci_name in the CMDB...")
	loggerObj.On("Debug", "ciLabel ci_name found: ")

	app.ObjectMeta.Labels = m
	ciLabel = "ci_name"
	ciName := p.getCIName(app)

	s.Assertions.Equal("", ciName, "No label found, assume empty string")
	loggerObj.AssertExpectations(t)
}

func (s *K8SRelatedTestSuite) TestGetCINameFilled() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	var app *argocd.Application = new(argocd.Application)
	var m map[string]string = make(map[string]string)

	loggerObj.On("Debug", "Search for ci_name in the CMDB...")
	loggerObj.On("Debug", "ciLabel ci_name found: app-demoapp")

	ciLabel = "ci_name"
	m[ciLabel] = "app-demoapp"
	app.ObjectMeta.Labels = m

	ciLabel := p.getCIName(app)

	s.Assertions.Equal("app-demoapp", ciLabel, "Label found, content app-demoapp")
	loggerObj.AssertExpectations(t)
}

func TestK8SRelated(t *testing.T) {
	suite.Run(t, new(K8SRelatedTestSuite))
}

func (s *PluginHelperMethodsTestSuite) TestGetGlobalVars() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	exampleUrl := "https://example.com"
	os.Setenv("SERVICE_NOW_URL", exampleUrl)
	os.Setenv("TIMEZONE", "")

	secretName := "snow-secret"
	namespace := "argocd-ephemeral-access"
	testUsername := "my-username"
	testPassword := "my-password"
	setCredentialsSecret(namespace, secretName, testUsername, testPassword)

	loggerObj.On("Debug", mock.Anything)

	unittest = true
	p.getGlobalVars()

	s.Assertions.Equal(exampleUrl, snowUrl, "snowURL should be retrieved from environment variables")
	s.Assertions.Equal("UTC", timezone, "Default timezone should be UTC")
	s.Assertions.Equal(testUsername, snowUsername, "SNOW username should be correct")
	s.Assertions.Equal(testPassword, snowPassword, "SNOW password should be correct")
	loggerObj.AssertExpectations(t)
}

func (s *PluginHelperMethodsTestSuite) TestShowRequest() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	var ar *api.AccessRequest = new(api.AccessRequest)
	var app *argocd.Application = new(argocd.Application)

	ar.Spec.Subject.Username = "Frederique"
	ar.Spec.Role.TemplateRef.Name = "administrator"
	ar.Spec.Application.Namespace = "argocd"
	ar.Spec.Application.Name = "demoapp"
	ar.Spec.Duration.Duration = time.Hour * 4

	jsonAr, _ := json.Marshal(ar)
	jsonApp, _ := json.Marshal(app)

	loggerObj.On("Info", "Call to GrantAccess: username: Frederique, role: administrator, application: [argocd]demoapp, duration: 4h0m0s")
	loggerObj.On("Debug", "jsonAr: "+string(jsonAr))
	loggerObj.On("Debug", "jsonApp: "+string(jsonApp))

	p.showRequest(ar, app)
	loggerObj.AssertExpectations(t)
}

func (s *PluginHelperMethodsTestSuite) TestProcessCI() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	ciName := "app-demoapp"
	responseText := fmt.Sprintf(`{"result":[{"install_status":"1", "name":"%s"}]}`, ciName)
	server, _ := testPrepareGetCI(t, loggerObj, ciName, responseText)
	defer server.Close()
	snowUrl = server.URL

	loggerObj.On("Debug", mock.Anything)

	errorString := p.processCI(ciName)

	s.Assertions.Equal("", errorString, "Errorstring should be empty")

	loggerObj.AssertExpectations(t)
}

func testConvertTimeToString(t time.Time) string {
	return fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
}

func (s *PluginHelperMethodsTestSuite) TestProcessChanges() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	timezone = "UTC"
	currentTime := time.Now()
	startDate := currentTime.Add(-5 * time.Minute)
	endDate := currentTime.Add(time.Hour * 2)

	ciName := "app-demoapp"
	requestURI := fmt.Sprintf("/api/now/table/change_request?cmdb_ci=%s&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date&sysparm_limit=5&sysparm_offset=0", ciName)
	responseText := fmt.Sprintf(`{"result":[{"type":"1", "number":"CHG300030", "short_description":"test", "start_date":"%s", "end_date":"%s"}]}`,
		testConvertTimeToString(startDate),
		testConvertTimeToString(endDate))

	var responseList map[string]string = make(map[string]string)
	responseList[requestURI] = responseText

	server := testPrepareGetChange(t, loggerObj, ciName, responseList)
	defer server.Close()
	snowUrl = server.URL

	loggerObj.On("Debug", mock.Anything)

	errorString, changeRemainingTime, validChange := p.processChanges(ciName)

	s.Assertions.Equal("", errorString, "Errorstring should be empty")
	if changeRemainingTime.Minutes() < 40 {
		s.Fail("changeRemainingTime is too small, less than 40 minutes")
	}

	s.Assertions.Equal("CHG300030", validChange.Number, "Numbers must be equal")
	s.Assertions.Equal("test", validChange.ShortDescription, "Short desciptions must be equal")
}

func (s *PluginHelperMethodsTestSuite) TestProcessChangesTwoWindows() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	timezone = "UTC"
	currentTime := time.Now()
	startDate := currentTime.Add(-5 * time.Minute)
	endDate := currentTime.Add(time.Hour * 2)

	ciName := "app-demoapp"
	var responseList map[string]string = make(map[string]string)

	requestURI := "/api/now/table/change_request?cmdb_ci=app-demoapp&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date&sysparm_limit=5&sysparm_offset=0"
	responseText := `{"result":[{"type":"1", "number":"CHG300030", "short_description":"test", "start_date":"2025-05-15 17:00:00", "end_date":"2025-05-15 17:45:00"},
                                {"type":"1", "number":"CHG300031", "short_description":"test2", "start_date":"2025-05-15 18:00:00", "end_date":"2025-05-15 18:45:00"},
                                {"type":"1", "number":"CHG300032", "short_description":"test3", "start_date":"2025-05-15 19:00:00", "end_date":"2025-05-15 19:45:00"},
                                {"type":"1", "number":"CHG300033", "short_description":"test4", "start_date":"2025-05-15 20:00:00", "end_date":"2025-05-15 20:45:00"},
                                {"type":"1", "number":"CHG300034", "short_description":"test5", "start_date":"2025-05-15 21:00:00", "end_date":"2025-05-15 21:45:00"}]}`

	responseList[requestURI] = responseText

	requestURI = "/api/now/table/change_request?cmdb_ci=app-demoapp&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date&sysparm_limit=5&sysparm_offset=5"
	responseText = fmt.Sprintf(`{"result":[{"type":"1", "number":"CHG300040", "short_description":"test6", "start_date":"2025-05-15 17:00:00", "end_date":"2025-05-15 17:45:00"},
                                {"type":"1", "number":"CHG300041", "short_description":"test7", "start_date":"2025-05-15 18:00:00", "end_date":"2025-05-15 18:45:00"},
                                {"type":"1", "number":"CHG300042", "short_description":"test8", "start_date":"2025-05-15 19:00:00", "end_date":"2025-05-15 19:45:00"},
                                {"type":"1", "number":"CHG300043", "short_description":"test9", "start_date":"2025-05-15 20:00:00", "end_date":"2025-05-15 20:45:00"},
                                {"type":"1", "number":"CHG300044", "short_description":"test10", "start_date":"%s", "end_date":"%s"}]}`,
		testConvertTimeToString(startDate),
		testConvertTimeToString(endDate))

	responseList[requestURI] = responseText

	server := testPrepareGetChange(t, loggerObj, ciName, responseList)
	defer server.Close()
	snowUrl = server.URL

	loggerObj.On("Debug", mock.Anything)

	errorString, changeRemainingTime, validChange := p.processChanges(ciName)

	s.Assertions.Equal("", errorString, "Errorstring should be empty")
	if changeRemainingTime.Minutes() < 40 {
		s.Fail("changeRemainingTime is too small, less than 40 minutes")
	}

	s.Assertions.Equal("CHG300044", validChange.Number, "Numbers must be equal")
	s.Assertions.Equal("test10", validChange.ShortDescription, "Short desciptions must be equal")
}

func (s *PluginHelperMethodsTestSuite) TestDenyAccess() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	reason := "whatever"
	response, err := p.denyAccess(reason)

	s.Assertions.Equal(plugin.GrantStatusDenied, response.Status, response, "Access request should be denied")
	s.Assertions.Equal(reason, response.Message, response, "Reason should be correct")
	s.Assertions.Equal(nil, err, "No error")

	loggerObj.AssertExpectations(t)
}

func setCredentialsSecret(namespace string, secretName string, username string, password string) {
	s := &coreV1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
		},
		Type: "Opaque",
		Data: map[string][]byte{
			"username": []byte(username),
			"password": []byte(password),
		},
	}

	k8sclientset = testclient.NewClientset()
	k8sclientset.CoreV1().Secrets(namespace).Create(context.TODO(), s, metav1.CreateOptions{})
}

func (s *PluginHelperMethodsTestSuite) TestGetSNOWCredentials() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	secretName := "snow-secret"
	namespace := "argocd-ephemeral-access"
	snowUsername := "SNOWUsername"
	snowPassword := "SNOWPassword"

	setCredentialsSecret(namespace, secretName, snowUsername, snowPassword)

	loggerObj.On("Debug", "Environment variable SECRET_NAMESPACE is empty, assuming argocd-ephemeral-access")
	loggerObj.On("Debug", "Environment variable SNOW_SECRET_NAME is empty, assuming snow-secret")
	loggerObj.On("Debug", "Get credentials from secret [argocd-ephemeral-access]snow-secret...")

	username, password := p.getSNOWCredentials()

	s.Assertions.Equal(snowUsername, username, "Username found")
	s.Assertions.Equal(snowPassword, password, "Password found")

	loggerObj.AssertExpectations(t)
}

func TestPluginHelperMethods(t *testing.T) {
	suite.Run(t, new(PluginHelperMethodsTestSuite))
}

func simulateSimpleHttpRequestToSNOW(t *testing.T, responseList map[string]string) *httptest.Server {

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := ""
		for uri, _ := range responseList {
			if uri == r.URL.RequestURI() {
				response = responseList[uri]
				break
			}
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("Expected Accept: application/json header, got: %s", r.Header.Get("Accept"))
		}
		usedUsername, usedPassword, ok := r.BasicAuth()
		if ok {
			assert.Equal(t, snowUsername, usedUsername, "Username that is used should match username that is requested")
			assert.Equal(t, snowPassword, usedPassword, "Password that is used should match username that is requested")
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(response))
	}))
	return server
}

func (s *SNOWTestSuite) TestGetFromSNOWAPIErrorInApiCall() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	responseText := "{\"results\":[]}"

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			if strings.Contains(fmt.Sprintf("%v", r), "no such host") {
				return
			}
			t.Error("Not correct panic text (expected 'no such host' in panic text)")
		}
		loggerObj.AssertExpectations(t)
	}()

	snowUsername = "testUser"
	snowPassword = "testPassword"
	ciName := "app-demoapp"

	var responseList map[string]string = make(map[string]string)
	requestURI := fmt.Sprintf("%s/api/now/table/cmdb_ci?name=%s&sysparm_fields=install_status,name", snowUrl, ciName)
	responseList[requestURI] = responseText

	server := simulateSimpleHttpRequestToSNOW(t, responseList)
	defer server.Close()
	snowUrl = server.URL

	apiCall := fmt.Sprintf("%s%s%s", server.URL, server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Error", mock.Anything)

	_ = p.getFromSNOWAPI(apiCall)
}

func (s *SNOWTestSuite) TestGetFromSNOWAPIServerDown() {
	t := s.T()
	p, loggerObj := testGetPlugin()
	errorText := "Service Now API server is down"
	responseText := "<html><body>Server down!</body></html>"

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			s.Assertions.Equal(errorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	snowUsername = "testUser"
	snowPassword = "testPassword"
	requestURI := "/api/test"

	var responseList map[string]string = make(map[string]string)
	responseList[requestURI] = responseText

	server := simulateSimpleHttpRequestToSNOW(t, responseList)
	defer server.Close()
	snowUrl = server.URL

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)
	loggerObj.On("Error", errorText)

	_ = p.getFromSNOWAPI(apiCall)
}

func (s *SNOWTestSuite) TestGetFromSNOWAPINormalResponse() {
	t := s.T()
	p, loggerObj := testGetPlugin()
	responseText := "{\"results\":[]}"

	snowUsername = "testUser"
	snowPassword = "testPassword"
	requestURI := "/api/test"

	var responseList map[string]string = make(map[string]string)
	responseList[requestURI] = responseText

	server := simulateSimpleHttpRequestToSNOW(t, responseList)
	defer server.Close()
	snowUrl = server.URL

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)

	result := p.getFromSNOWAPI(apiCall)
	s.Assertions.Equal(responseText, string(result), "Correct result from API")
}

func (s *SNOWTestSuite) TestGetCIServerDown() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	errorText := "Service Now API server is down"
	responseText := "<html><body>Server down!</body></html>"

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			s.Assertions.Equal(errorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	snowUsername = "testUser"
	snowPassword = "testPassword"
	ciName := "app-demoapp"
	requestURI := fmt.Sprintf("/api/now/table/cmdb_ci?name=%s&sysparm_fields=install_status,name", ciName)

	var responseList map[string]string = make(map[string]string)
	responseList[requestURI] = responseText

	server := simulateSimpleHttpRequestToSNOW(t, responseList)
	defer server.Close()

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)
	loggerObj.On("Error", errorText)
	defer server.Close()

	snowUrl = server.URL

	_ = p.getCI("app-demoapp")
}

func (s *SNOWTestSuite) TestGetCINoJSON() {
	t := s.T()
	p, loggerObj := testGetPlugin()
	errorText := "Error in json.Unmarshal: invalid character '<' looking for beginning of value (<Result/>)"
	responseText := "<Result/>"

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			s.Assertions.Equal(errorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	snowUsername = "testUser"
	snowPassword = "testPassword"
	ciName := "app-demoapp"
	requestURI := fmt.Sprintf("/api/now/table/cmdb_ci?name=%s&sysparm_fields=install_status,name", ciName)

	var responseList map[string]string = make(map[string]string)
	responseList[requestURI] = responseText

	server := simulateSimpleHttpRequestToSNOW(t, responseList)
	defer server.Close()

	snowUrl = server.URL

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)
	loggerObj.On("Error", errorText)

	_ = p.getCI(ciName)
}

func (s *SNOWTestSuite) TestGetChangeServerDown() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	responseText := "<html><body>Server down!</body></html>"
	errorText := "Service Now API server is down"

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			s.Assertions.Equal(errorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	snowUsername = "testUser"
	snowPassword = "testPassword"
	ciName := "app-demoapp"
	requestURI := fmt.Sprintf("/api/now/table/change_request?cmdb_ci=%s&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date&sysparm_limit=5&sysparm_offset=0", ciName)

	var responseList map[string]string = make(map[string]string)
	responseList[requestURI] = responseText

	server := simulateSimpleHttpRequestToSNOW(t, responseList)
	defer server.Close()

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)
	loggerObj.On("Error", errorText)
	defer server.Close()

	snowUrl = server.URL

	_, _ = p.getChanges("app-demoapp", 0)
}

func (s *SNOWTestSuite) TestGetChangeNoJSON() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	responseText := "!"
	errorText := "Error in json.Unmarshal: invalid character '!' looking for beginning of value (!)"

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			s.Assertions.Equal(errorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	snowUsername = "testUser"
	snowPassword = "testPassword"
	ciName := "app-demoapp"
	requestURI := fmt.Sprintf("/api/now/table/change_request?cmdb_ci=%s&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date&sysparm_limit=5&sysparm_offset=0", ciName)

	var responseList map[string]string = make(map[string]string)
	responseList[requestURI] = responseText

	server := simulateSimpleHttpRequestToSNOW(t, responseList)
	defer server.Close()

	snowUrl = server.URL

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)
	loggerObj.On("Error", errorText)

	_, _ = p.getChanges(ciName, 0)
}

func TestSNOWMethods(t *testing.T) {
	suite.Run(t, new(SNOWTestSuite))
}

func (s *CITestSuite) TestGetCINoCI() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	responseText := "{\"result\":[]}"
	errorText := "No CI with name app-demoapp found"

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			s.Assertions.Equal(errorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	snowUsername = "testUser"
	snowPassword = "testPassword"
	ciName := "app-demoapp"
	requestURI := fmt.Sprintf("/api/now/table/cmdb_ci?name=%s&sysparm_fields=install_status,name", ciName)

	var responseList map[string]string = make(map[string]string)
	responseList[requestURI] = responseText

	server := simulateSimpleHttpRequestToSNOW(t, responseList)
	defer server.Close()

	snowUrl = server.URL
	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)
	loggerObj.On("Error", errorText)

	_ = p.getCI(ciName)
}

func testPrepareGetCI(t *testing.T, loggerObj *MockedLogger, ciName string, responseText string) (*httptest.Server, string) {
	snowUsername = "testUser"
	snowPassword = "testPassword"
	requestURI := fmt.Sprintf("/api/now/table/cmdb_ci?name=%s&sysparm_fields=install_status,name", ciName)

	var responseList map[string]string = make(map[string]string)
	responseList[requestURI] = responseText

	server := simulateSimpleHttpRequestToSNOW(t, responseList)
	snowUrl = server.URL

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)
	loggerObj.On("Debug", fmt.Sprintf("InstallStatus: 1, CI name: %s", ciName))

	return server, apiCall
}

func (s *CITestSuite) TestGetCIOneCI() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	ciName := "app-demoapp"
	responseText := fmt.Sprintf(`{"result":[{"install_status":"1", "name":"%s"}]}`, ciName)
	server, _ := testPrepareGetCI(t, loggerObj, ciName, responseText)
	defer server.Close()

	cmdb := p.getCI(ciName)

	s.Assertions.Equal("1", cmdb.InstallStatus, "InstallStatus should be 1")
	s.Assertions.Equal(ciName, cmdb.Name, "Name should be "+ciName)
	loggerObj.AssertExpectations(t)
}

func (s *CITestSuite) TestGetCITwoCIs() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	ciName := "app-demoapp"
	responseText := "{\"result\":[{\"install_status\":\"1\", \"name\":\"app-demoapp\"},{\"install_status\":\"6\", \"name\":\"app-demoapp\"}]}"
	server, apiCall := testPrepareGetCI(t, loggerObj, ciName, responseText)
	defer server.Close()

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)
	loggerObj.On("Debug", "InstallStatus: 1, CI name: app-demoapp")

	cmdb := p.getCI(ciName)

	s.Assertions.Equal("1", cmdb.InstallStatus, "InstallStatus should be 1")
	s.Assertions.Equal(ciName, cmdb.Name, "Name should be "+ciName)
	loggerObj.AssertExpectations(t)
}

func TestCIMethods(t *testing.T) {
	suite.Run(t, new(CITestSuite))
}

func (s *ChangeTestSuite) TestGetChangeNoChange() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	responseText := "{\"result\":[]}"
	errorText := "No changes found"

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			s.Assertions.Equal(errorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	snowUsername = "testUser"
	snowPassword = "testPassword"
	ciName := "app-demoapp"
	requestURI := fmt.Sprintf("/api/now/table/change_request?cmdb_ci=%s&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date&sysparm_limit=5&sysparm_offset=0", ciName)

	var responseList map[string]string = make(map[string]string)
	responseList[requestURI] = responseText

	server := simulateSimpleHttpRequestToSNOW(t, responseList)
	defer server.Close()

	snowUrl = server.URL

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)
	loggerObj.On("Error", errorText)

	_, _ = p.getChanges(ciName, 0)
}

func testPrepareGetChange(t *testing.T, loggerObj *MockedLogger, ciName string, responseList map[string]string) *httptest.Server {
	snowUsername = "testUser"
	snowPassword = "testPassword"

	server := simulateSimpleHttpRequestToSNOW(t, responseList)
	snowUrl = server.URL

	return server
}

func (s *ChangeTestSuite) TestGetChangesOneChange() {
	t := s.T()

	p, loggerObj := testGetPlugin()

	ciName := "app-demoapp"
	responseText := `{"result":[{"type":"1", "number":"CHG300030", "short_description":"test", "start_date":"2025-05-15 17:00:00", "end_date":"2025-05-15 17:45:00"}]}`
	requestURI := fmt.Sprintf("/api/now/table/change_request?cmdb_ci=%s&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date&sysparm_limit=5&sysparm_offset=0", ciName)

	var responseList map[string]string = make(map[string]string)
	responseList[requestURI] = responseText

	server := testPrepareGetChange(t, loggerObj, ciName, responseList)
	defer server.Close()
	snowUrl = server.URL

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)

	changes, number := p.getChanges(ciName, 0)

	s.Assertions.Equal("CHG300030", changes[0].Number, "Change number should be the same as in the API result")
	s.Assertions.Equal(1, number, "Number should be incremented by the number of changes that are received")

	loggerObj.AssertExpectations(t)
}

func (s *ChangeTestSuite) TestGetChangesTwoChanges() {
	t := s.T()

	p, loggerObj := testGetPlugin()

	ciName := "app-demoapp"
	requestURI := fmt.Sprintf("/api/now/table/change_request?cmdb_ci=%s&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date&sysparm_limit=5&sysparm_offset=0", ciName)
	responseText := `{"result":[{"type":"1", "number":"CHG300030", "short_description":"test", "start_date":"2025-05-15 17:00:00", "end_date":"2025-05-15 17:45:00"},
                                {"type":"1", "number":"CHG300031", "short_description":"test2", "start_date":"2025-05-15 18:00:00", "end_date":"2025-05-15 18:45:00"}]}`

	var responseList map[string]string = make(map[string]string)
	responseList[requestURI] = responseText

	server := testPrepareGetChange(t, loggerObj, ciName, responseList)
	defer server.Close()

	snowUrl = server.URL

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)
	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)

	changes, number := p.getChanges(ciName, 0)

	s.Assertions.Equal("CHG300030", changes[0].Number, "Change number should be the same as in the API result")
	s.Assertions.Equal(2, number, "Number should be incremented by the number of changes that are received")
	s.Assertions.Equal("CHG300031", changes[1].Number, "Change number should be the same as in the API result")

	loggerObj.AssertExpectations(t)
}

func (s *ChangeTestSuite) TestGetChangesExactWindowSize() {
	t := s.T()

	p, loggerObj := testGetPlugin()

	ciName := "app-demoapp"
	requestURI := fmt.Sprintf("/api/now/table/change_request?cmdb_ci=%s&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date&sysparm_limit=5&sysparm_offset=0", ciName)
	responseText := `{"result":[{"type":"1", "number":"CHG300030", "short_description":"test", "start_date":"2025-05-15 17:00:00", "end_date":"2025-05-15 17:45:00"},
                                {"type":"1", "number":"CHG300031", "short_description":"test2", "start_date":"2025-05-15 18:00:00", "end_date":"2025-05-15 18:45:00"},
                                {"type":"1", "number":"CHG300032", "short_description":"test3", "start_date":"2025-05-15 19:00:00", "end_date":"2025-05-15 19:45:00"},
                                {"type":"1", "number":"CHG300033", "short_description":"test4", "start_date":"2025-05-15 20:00:00", "end_date":"2025-05-15 20:45:00"},
                                {"type":"1", "number":"CHG300034", "short_description":"test5", "start_date":"2025-05-15 21:00:00", "end_date":"2025-05-15 21:45:00"}]}`

	var responseList map[string]string = make(map[string]string)
	responseList[requestURI] = responseText

	server := testPrepareGetChange(t, loggerObj, ciName, responseList)
	defer server.Close()

	snowUrl = server.URL

	loggerObj.On("Debug", mock.Anything)

	changes, number := p.getChanges(ciName, 0)

	s.Assertions.Equal("CHG300030", changes[0].Number, "Change number should be the same as in the API result")
	s.Assertions.Equal(5, number, "Number should be incremented by the number of changes that are received")
	s.Assertions.Equal("CHG300031", changes[1].Number, "Change number should be the same as in the API result")
	s.Assertions.Equal("CHG300032", changes[2].Number, "Change number should be the same as in the API result")
	s.Assertions.Equal("CHG300033", changes[3].Number, "Change number should be the same as in the API result")
	s.Assertions.Equal("CHG300034", changes[4].Number, "Change number should be the same as in the API result")

	loggerObj.AssertExpectations(t)
}

func (s *ChangeTestSuite) TestParseChange() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	var change_snow = change_snow_type{
		Type:             "1",
		Number:           "CHG12345",
		State:            -1.0,
		Phase:            "1",
		CMDBCi:           "app-demoapp",
		Active:           "1",
		EndDate:          "2025-05-16 23:59:59",
		ShortDescription: "Test",
		StartDate:        "2025-05-16 08:00:00",
		Approval:         "1",
	}

	loggerObj.On("Debug", fmt.Sprintf("Change: Type: %s, Short description: %s, Start Date: %s, End Date: %s",
		change_snow.Type,
		change_snow.ShortDescription,
		change_snow.StartDate,
		change_snow.EndDate))

	chg := p.parseChange(change_snow)

	s.Assertions.Equal(change_snow.Type, chg.Type, "Change type should be the same")
	s.Assertions.Equal(change_snow.Number, chg.Number, "Change number should be the same")
	s.Assertions.Equal(change_snow.State, chg.State, "Change state should be the same")
	s.Assertions.Equal(change_snow.Phase, chg.Phase, "Change phase should be the same")
	s.Assertions.Equal(change_snow.CMDBCi, chg.CMDBCi, "Change CI should be the same")
	s.Assertions.Equal(change_snow.Active, chg.Active, "Change active state should be the same")
	s.Assertions.Equal(time.Date(2025, 05, 16, 23, 59, 59, 0, time.UTC), chg.EndDate, "Change end date should be the same")
	s.Assertions.Equal(change_snow.ShortDescription, chg.ShortDescription, "Change short description should be the same")
	s.Assertions.Equal(time.Date(2025, 05, 16, 8, 0, 0, 0, time.UTC), chg.StartDate, "Change start date should be the same")
	s.Assertions.Equal(change_snow.Approval, chg.Approval, "Change approval state should be the same")

	loggerObj.AssertExpectations(t)
}

func TestChangeMethods(t *testing.T) {
	suite.Run(t, new(ChangeTestSuite))
}

func testAllowedCIStatus(s *CheckCITestSuite, status string) {
	t := s.T()
	p, loggerObj := testGetPlugin()

	var ci = cmdb_snow_type{
		InstallStatus: status,
		Name:          "whatever",
	}

	checkString := p.checkCI(ci)
	s.Assertions.Equal("", checkString, "Installed state should be accepted")
	loggerObj.AssertExpectations(t)
}

func testNotAllowedCIStatus(s *CheckCITestSuite, status string) {
	t := s.T()
	p, loggerObj := testGetPlugin()

	var ci = cmdb_snow_type{
		InstallStatus: status,
		Name:          "whatever",
	}

	checkString := p.checkCI(ci)
	expectedCheckString := fmt.Sprintf("Invalid install status (%s) for CI whatever", status)
	s.Assertions.Equal(expectedCheckString, checkString, "Other states should not be accepted")

	loggerObj.AssertExpectations(t)
}

func (s *CheckCITestSuite) TestCheckCIInstalled() {
	testAllowedCIStatus(s, "1") // Installed
}

func (s *CheckCITestSuite) TestCheckCIInMaintenance() {
	testAllowedCIStatus(s, "3") // In maintenance
}

func (s *CheckCITestSuite) TestCheckCIPendingInstall() {
	testAllowedCIStatus(s, "4") // Pending Install
}

func (s *CheckCITestSuite) TestCheckCIPendingRepair() {
	testAllowedCIStatus(s, "5") // Pending Repair
}

func (s *CheckCITestSuite) TestCheckCIStateNotAllowed0() {
	testNotAllowedCIStatus(s, "0")
}

func (s *CheckCITestSuite) TestCheckCIState2() {
	testNotAllowedCIStatus(s, "2")
}

func (s *CheckCITestSuite) TestCheckCIState6() {
	testNotAllowedCIStatus(s, "6")
}

func TestCheckCI(t *testing.T) {
	suite.Run(t, new(CheckCITestSuite))
}

func testChangeTimeIncorrect(s *CheckChangeTestSuite, currentTime time.Time, startDate time.Time, endDate time.Time) {
	t := s.T()
	p, loggerObj := testGetPlugin()

	timezone = "UTC"

	var change = change_type{
		Type:             "1",
		Number:           "CHG12345",
		State:            -1.0,
		Phase:            "1",
		CMDBCi:           "app-demoapp",
		Active:           "1",
		EndDate:          endDate,
		ShortDescription: "Test",
		StartDate:        startDate,
		Approval:         "1",
	}

	expectedErrorText := fmt.Sprintf("Change %s (%s) is not in the valid time range. start date: %s and end date: %s (current date: %s)",
		change.Number,
		change.ShortDescription,
		p.getLocalTime(change.StartDate),
		p.getLocalTime(change.EndDate),
		p.getLocalTime(currentTime))
	loggerObj.On("Debug", expectedErrorText)

	checkString, _ := p.checkChange(change)

	assert.Equal(t, expectedErrorText, checkString, "Change that is started too early should not be accepted")
	loggerObj.AssertExpectations(t)

}

func (s *CheckChangeTestSuite) TestCheckChangeTooEarly() {
	currentTime := time.Now()
	startDate := currentTime.Add(time.Hour)
	endDate := currentTime.Add(time.Hour * 2)

	testChangeTimeIncorrect(s, currentTime, startDate, endDate)
}

func (s *CheckChangeTestSuite) TestCheckChangeCorrectTime() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	timezone = "UTC"
	currentTime := time.Now()
	startDate := currentTime.Add(-5 * time.Minute)
	endDate := currentTime.Add(time.Hour * 2)

	var change = change_type{
		Type:             "1",
		Number:           "CHG12345",
		State:            -1.0,
		Phase:            "1",
		CMDBCi:           "app-demoapp",
		Active:           "1",
		EndDate:          endDate,
		ShortDescription: "Test",
		StartDate:        startDate,
		Approval:         "1",
	}

	expectedErrorText := ""

	checkString, remainingTime := p.checkChange(change)

	assert.Equal(t, expectedErrorText, checkString, "Change that is started between start date and end date should be accepted")
	assert.Equal(t, time.Duration(time.Hour*2), remainingTime, "Remaining time should be correct")
	loggerObj.AssertExpectations(t)
}

func (s *CheckChangeTestSuite) TestCheckChangeTooLate() {
	timezone = "UTC"
	currentTime := time.Now()
	startDate := currentTime.Add(-2 * time.Hour)
	endDate := currentTime.Add(-1 * time.Hour)

	testChangeTimeIncorrect(s, currentTime, startDate, endDate)
}

func TestCheckChange(t *testing.T) {
	suite.Run(t, new(CheckChangeTestSuite))
}

func simulateGlobalHttpRequestToSNOW(startDateString string, endDateString string, installStatus string) *httptest.Server {

	var response string

	time.Local = time.UTC
	timezone = "UTC"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RequestURI() == "/api/now/table/cmdb_ci?name=app-demoapp&sysparm_fields=install_status,name" {
			response = fmt.Sprintf(`{"result": [{"install_status": "%s", "name": "demoapp"}]}`, installStatus)
		}
		if r.URL.RequestURI() == "/api/now/table/change_request?cmdb_ci=app-demoapp&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date&sysparm_limit=5&sysparm_offset=0" {
			response = fmt.Sprintf(`{"result":[{"type":"1", "number":"CHG300030", "short_description":"valid change", "start_date":"%s", "end_date":"%s"}]}`, startDateString, endDateString)
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(response))
	}))
	return server
}

func testGetArApp() (api.AccessRequest, argocd.Application) {
	var ar api.AccessRequest
	var requestedRole api.TargetRole
	var app argocd.Application

	requestedRole.TemplateRef.Name = "administrator"

	ar.Spec.Subject.Username = "Test User"
	ar.Spec.Role = requestedRole
	ar.Spec.Application.Namespace = "argocd"
	ar.Spec.Application.Name = "demoapp"
	ar.Spec.Duration.Duration = 4 * time.Hour

	app.ObjectMeta.Name = "demoapp"

	var m map[string]string = make(map[string]string)
	m["ci_name"] = "app-demoapp"
	app.ObjectMeta.Labels = m

	return ar, app
}

func (s *PublicMethodsTestSuite) TestInit() {
	t := s.T()

	p, loggerObj := testGetPlugin()
	loggerObj.On("Debug", "This is a call to the Init method")

	result := p.Init()

	s.Assertions.Equal(nil, result, "Init correctly executed")
	loggerObj.AssertExpectations(t)
}

func (s *PublicMethodsTestSuite) TestGrantAccess() {
	t := s.T()

	p, loggerObj := testGetPlugin()

	unittest = true // don't initialize k8sconfig/k8sclientset

	ar, app := testGetArApp()

	os.Setenv("TIMEZONE", "UTC")
	currentTime := time.Now()
	startDate := currentTime.Add(-5 * time.Minute)
	endDate := currentTime.Add(2 * time.Hour)
	startDateString := fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", startDate.Year(), startDate.Month(), startDate.Day(), startDate.Hour(), startDate.Minute(), startDate.Second())
	endDateString := fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", endDate.Year(), endDate.Month(), endDate.Day(), endDate.Hour(), endDate.Minute(), endDate.Second())

	loggerObj.On("Debug", mock.Anything)
	loggerObj.On("Info", mock.Anything)

	var responseList map[string]string = make(map[string]string)

	requestURI := "/api/now/table/cmdb_ci?name=app-demoapp&sysparm_fields=install_status,name"
	responseText := `{"result": [{"install_status": "1", "name": "demoapp"}]}`
	responseList[requestURI] = responseText

	requestURI = "/api/now/table/change_request?cmdb_ci=app-demoapp&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date&sysparm_limit=5&sysparm_offset=0"
	responseText = fmt.Sprintf(`{"result":[{"type":"1", "number":"CHG300030", "short_description":"valid change", "start_date":"%s", "end_date":"%s"}]}`, startDateString, endDateString)
	responseList[requestURI] = responseText

	server := simulateSimpleHttpRequestToSNOW(t, responseList)
	defer server.Close()

	os.Setenv("SERVICE_NOW_URL", server.URL)

	secretName := "snow-secret"
	namespace := "argocd-ephemeral-access"
	genericUsername := "SNOWUsername"
	genericPassword := "SNOWPassword"

	setCredentialsSecret(namespace, secretName, genericUsername, genericPassword)

	response, err := p.GrantAccess(&ar, &app)

	s.Assertions.Equal(plugin.GrantStatusGranted, response.Status, "Status should be granted")
	s.Assertions.Equal(nil, err, "Error should be nil")
	if !strings.Contains(response.Message, "Granted access") {
		t.Errorf("%s should contain text Granted access", response.Message)
	}
	loggerObj.AssertExpectations(t)
}

func (s *PublicMethodsTestSuite) TestGrantAccessNoCIName() {
	t := s.T()

	p, loggerObj := testGetPlugin()

	errorText := "No CI name found: expected label with name ci_name in application demoapp"

	ar, app := testGetArApp()
	var m map[string]string = make(map[string]string)
	m["ci_name"] = "\"\""
	app.ObjectMeta.Labels = m

	unittest = true

	loggerObj.On("Debug", mock.Anything)
	loggerObj.On("Info", "Call to GrantAccess: username: Test User, role: administrator, application: [argocd]demoapp, duration: 4h0m0s")
	loggerObj.On("Error", errorText)
	response, err := p.GrantAccess(&ar, &app)

	s.Assertions.Equal(errorText, response.Message, "Response message should be correct")
	s.Assertions.Equal(plugin.GrantStatusDenied, response.Status, "Response status should be correct")
	s.Assertions.Equal(nil, err, "Error should be nil")

	loggerObj.AssertExpectations(t)
}

func (s *PublicMethodsTestSuite) TestGrantAccessIncorrectCI() {
	t := s.T()

	p, loggerObj := testGetPlugin()
	ar, app := testGetArApp()

	unittest = true

	startDateString := "2025-01-01 00:00:00"
	endDateString := "2025-01-01 23:59:59"
	installStatus := "-1"
	server := simulateGlobalHttpRequestToSNOW(startDateString, endDateString, installStatus)
	defer server.Close()
	os.Setenv("SERVICE_NOW_URL", server.URL)

	errorText := fmt.Sprintf("Invalid install status (%s) for CI demoapp", installStatus)

	loggerObj.On("Debug", mock.Anything)
	loggerObj.On("Info", mock.Anything)
	loggerObj.On("Error", "Access Denied for Test User : "+errorText)
	response, err := p.GrantAccess(&ar, &app)

	s.Assertions.Equal(errorText, response.Message, "Response message should be correct")
	s.Assertions.Equal(plugin.GrantStatusDenied, response.Status, "Response status should be correct")
	s.Assertions.Equal(nil, err, "Error should be nil")

	loggerObj.AssertExpectations(t)
}

func (s *PublicMethodsTestSuite) TestGrantAccessNoChange() {
	t := s.T()

	p, loggerObj := testGetPlugin()
	ar, app := testGetArApp()

	unittest = true

	startDateString := "2025-01-01 00:00:00"
	endDateString := "2025-01-01 23:59:59"
	installStatus := "1"
	server := simulateGlobalHttpRequestToSNOW(startDateString, endDateString, installStatus)
	defer server.Close()
	os.Setenv("SERVICE_NOW_URL", server.URL)

	loggerObj.On("Debug", mock.Anything)
	loggerObj.On("Info", mock.Anything)
	loggerObj.On("Error", mock.Anything)
	response, err := p.GrantAccess(&ar, &app)

	containsCorrectText := strings.Contains(response.Message, "is not in the valid time range. start date: 00:00:00 and end date: 23:59:59")
	if !containsCorrectText {
		s.Assertions.Fail("Response message should be correct")
	}
	s.Assertions.Equal(plugin.GrantStatusDenied, response.Status, "Response status should be correct")
	s.Assertions.Equal(nil, err, "Error should be nil")

	loggerObj.AssertExpectations(t)
}

func (s *PublicMethodsTestSuite) TestRevokeAccess() {
	p, _ := testGetPlugin()

	var ar api.AccessRequest
	var app argocd.Application

	var expectedResponse *plugin.RevokeResponse = nil

	response, err := p.RevokeAccess(&ar, &app)
	s.Assertions.Equal(expectedResponse, response, "Revoke Access is not used, expect nil")
	s.Assertions.Equal(nil, err, "Error should be nil")
}

func TestPublicMethods(t *testing.T) {
	suite.Run(t, new(PublicMethodsTestSuite))
}
