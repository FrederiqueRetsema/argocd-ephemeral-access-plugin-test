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

	argocd "github.com/argoproj-labs/argocd-ephemeral-access/api/argoproj/v1alpha1"
	api "github.com/argoproj-labs/argocd-ephemeral-access/api/ephemeral-access/v1alpha1"

	coreV1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	testclient "k8s.io/client-go/kubernetes/fake"
)

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

func testGetP() (*ServiceNowPlugin, *MockedLogger) {
	loggerObj := new(MockedLogger)

	p := &ServiceNowPlugin{
		Logger: loggerObj,
	}

	return p, loggerObj
}

func TestInit(t *testing.T) {

	p, loggerObj := testGetP()
	loggerObj.On("Debug", "This is a call to the Init method")
	result := p.Init()
	assert.Equal(t, nil, result, "Init correctly executed")
	loggerObj.AssertExpectations(t)
}

func TestGetEnvVarWithPanicNoEnvVar(t *testing.T) {
	p, loggerObj := testGetP()
	errorText := "Panic!"

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			assert.Equal(t, errorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	snowUrl = ""
	os.Setenv("SERVICE_NOW_URL", "")
	loggerObj.On("Error", errorText)

	snowUrl = p.getEnvVarWithPanic("SERVICE_NOW_URL", errorText)

	t.Errorf("The code did not panic")
}

func TestGetEnvVarWithPanicWithEnvVar(t *testing.T) {
	p, loggerObj := testGetP()
	snowUrl = ""
	os.Setenv("SERVICE_NOW_URL", "https://example.com")

	snowUrl = p.getEnvVarWithPanic("SERVICE_NOW_URL", "Panic!")

	assert.Equal(t, "https://example.com", snowUrl, "The correct URL is retrieved")
	loggerObj.AssertExpectations(t)
}

func TestGetEnvVarWithDefaultNoEnvVar(t *testing.T) {
	p, loggerObj := testGetP()
	os.Setenv("TIMEZONE", "")
	loggerObj.On("Debug", "Environment variable TIMEZONE is empty, assuming UTC")
	timezone := p.getEnvVarWithDefault("TIMEZONE", "UTC")
	assert.Equal(t, "UTC", timezone, "Assumed UTC correctly")
	loggerObj.AssertExpectations(t)
}

func TestGetEnvVarWithDefaultWithEnvVar(t *testing.T) {
	p, loggerObj := testGetP()
	os.Setenv("TIMEZONE", "Amsterdam/Europe")
	timezone := p.getEnvVarWithDefault("TIMEZONE", "UTC")
	assert.Equal(t, "Amsterdam/Europe", timezone, "Environment TIMEZONE was filled, Retrieved Amsterdam/Europe correctly")
	loggerObj.AssertExpectations(t)
}

func TestGetK8sConfig(t *testing.T) {
	// Will always panic because the tests are not run from within a Kubernetes cluster
	// Running this correctly, not just some environment variables must be set, but also a directory structure
	// for retrieving the token
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
		}
	}()

	p, _ := testGetP()
	os.Setenv("KUBERNETES_SERVICE_HOST", "https://kubernetes.example.com")
	os.Setenv("KUBERNETES_SERVICE_PORT", "6443")
	p.getK8sConfig()
	t.Errorf("The code did not panic")
}

func TestGetCINameEmpty(t *testing.T) {
	p, loggerObj := testGetP()
	var app *argocd.Application = new(argocd.Application)
	var m map[string]string

	loggerObj.On("Debug", "ciLabel ci_name found: ")

	app.ObjectMeta.Labels = m
	ciLabel := p.getCIName(app, "ci_name")

	assert.Equal(t, "", ciLabel, "No label found, assume empty string")
	loggerObj.AssertExpectations(t)
}

func TestGetCINameFilled(t *testing.T) {
	p, loggerObj := testGetP()
	var app *argocd.Application = new(argocd.Application)
	var m map[string]string = make(map[string]string)

	loggerObj.On("Debug", "ciLabel ci_name found: app-demoapp")

	m["ci_name"] = "app-demoapp"
	app.ObjectMeta.Labels = m

	ciLabel := p.getCIName(app, "ci_name")

	assert.Equal(t, "app-demoapp", ciLabel, "Label found, content app-demoapp")
	loggerObj.AssertExpectations(t)
}

func TestShowRequest(t *testing.T) {
	p, loggerObj := testGetP()
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

func TestGetCredentialsFromSecretSecretDoesntExist(t *testing.T) {
	p, loggerObj := testGetP()

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			assert.Equal(t, "secrets \"does-not-exist\" not found", fmt.Sprintf("%v", r), "Panic text is correct")
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

func TestGetCredentialsFromSecret(t *testing.T) {
	p, loggerObj := testGetP()

	secretName := "generic-secret"
	namespace := "generic-namespace"
	genericUsername := "GenericUsername"
	genericPassword := "GenericPassword"

	setCredentialsSecret(namespace, secretName, genericUsername, genericPassword)

	loggerObj.On("Debug", fmt.Sprintf("Get credentials from secret [%s]%s...", namespace, secretName))

	username, password := p.getCredentialsFromSecret(namespace, secretName, "username", "password")

	assert.Equal(t, genericUsername, username, "Username found")
	assert.Equal(t, genericPassword, password, "Password found")
	loggerObj.AssertExpectations(t)
}

func TestGetSNOWCredentials(t *testing.T) {
	p, loggerObj := testGetP()

	secretName := "snow-secret"
	namespace := "argocd-ephemeral-access"
	snowUsername := "SNOWUsername"
	snowPassword := "SNOWPassword"

	setCredentialsSecret(namespace, secretName, snowUsername, snowPassword)

	loggerObj.On("Debug", "Environment variable SECRET_NAMESPACE is empty, assuming argocd-ephemeral-access")
	loggerObj.On("Debug", "Environment variable SNOW_SECRET_NAME is empty, assuming snow-secret")
	loggerObj.On("Debug", "Get credentials from secret [argocd-ephemeral-access]snow-secret...")

	username, password := p.getSNOWCredentials()

	assert.Equal(t, snowUsername, username, "Username found")
	assert.Equal(t, snowPassword, password, "Password found")
	loggerObj.AssertExpectations(t)
}

func simulateHttpRequestToSNOW(t *testing.T, username string, password string, requestURI string, response string) *httptest.Server {

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RequestURI() != requestURI {
			t.Errorf("Expected to request '%s', got: %s", requestURI, r.URL.Path)
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("Expected Accept: application/json header, got: %s", r.Header.Get("Accept"))
		}
		usedUsername, usedPassword, ok := r.BasicAuth()
		if ok {
			assert.Equal(t, username, usedUsername, "Username that is used should match username that is requested")
			assert.Equal(t, password, usedPassword, "Password that is used should match username that is requested")
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(response))
	}))
	return server
}

func TestGetFromSNOWAPIErrorInApiCall(t *testing.T) {
	p, loggerObj := testGetP()
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

	username := "testUser"
	password := "testPassword"
	requestURI := "/api/test"
	server := simulateHttpRequestToSNOW(t, username, password, requestURI, responseText)
	defer server.Close()

	apiCall := fmt.Sprintf("%s%s%s", server.URL, server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Error", mock.Anything)

	_ = p.getFromSNOWAPI(username, password, apiCall)
}

func TestGetFromSNOWAPIServerDown(t *testing.T) {
	p, loggerObj := testGetP()
	errorText := "Service Now API server is down"
	responseText := "<html><body>Server down!</body></html>"

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			assert.Equal(t, errorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	username := "testUser"
	password := "testPassword"
	requestURI := "/api/test"
	server := simulateHttpRequestToSNOW(t, username, password, requestURI, responseText)
	defer server.Close()

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)
	loggerObj.On("Error", errorText)

	_ = p.getFromSNOWAPI(username, password, apiCall)
}

func TestGetFromSNOWAPINormalResponse(t *testing.T) {
	p, loggerObj := testGetP()
	responseText := "{\"results\":[]}"

	username := "testUser"
	password := "testPassword"
	requestURI := "/api/test"
	server := simulateHttpRequestToSNOW(t, username, password, requestURI, responseText)
	defer server.Close()

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)

	result := p.getFromSNOWAPI(username, password, apiCall)
	assert.Equal(t, responseText, string(result), "Correct result from API")
}

func TestGetCIServerDown(t *testing.T) {
	p, loggerObj := testGetP()
	errorText := "Service Now API server is down"
	responseText := "<html><body>Server down!</body></html>"

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			assert.Equal(t, errorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	username := "testUser"
	password := "testPassword"
	ciName := "app-demoapp"
	requestURI := fmt.Sprintf("/api/now/table/cmdb_ci?name=%s&sysparm_fields=install_status,name", ciName)
	server := simulateHttpRequestToSNOW(t, username, password, requestURI, responseText)

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)
	loggerObj.On("Error", errorText)
	defer server.Close()

	snowUrl = server.URL

	_ = p.getCI(username, password, "app-demoapp")
}

func TestGetCINoJSON(t *testing.T) {
	p, loggerObj := testGetP()
	errorText := "Error in json.Unmarshal: invalid character '<' looking for beginning of value"
	responseText := "<Result/>"

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			assert.Equal(t, errorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	username := "testUser"
	password := "testPassword"
	ciName := "app-demoapp"
	requestURI := fmt.Sprintf("/api/now/table/cmdb_ci?name=%s&sysparm_fields=install_status,name", ciName)
	server := simulateHttpRequestToSNOW(t, username, password, requestURI, responseText)
	defer server.Close()

	snowUrl = server.URL

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)
	loggerObj.On("Error", errorText)

	_ = p.getCI(username, password, ciName)
}

func TestGetCINoCI(t *testing.T) {
	p, loggerObj := testGetP()
	errorText := "No CI with name app-demoapp found"
	responseText := "{\"result\":[]}"

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			assert.Equal(t, errorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	username := "testUser"
	password := "testPassword"
	ciName := "app-demoapp"
	requestURI := fmt.Sprintf("/api/now/table/cmdb_ci?name=%s&sysparm_fields=install_status,name", ciName)
	server := simulateHttpRequestToSNOW(t, username, password, requestURI, responseText)
	defer server.Close()

	snowUrl = server.URL

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)
	loggerObj.On("Error", errorText)

	_ = p.getCI(username, password, ciName)
}

func TestGetCIOneCI(t *testing.T) {
	p, loggerObj := testGetP()
	responseText := "{\"result\":[{\"install_status\":\"1\", \"name\":\"app-demoapp\"}]}"

	username := "testUser"
	password := "testPassword"
	ciName := "app-demoapp"
	requestURI := fmt.Sprintf("/api/now/table/cmdb_ci?name=%s&sysparm_fields=install_status,name", ciName)
	server := simulateHttpRequestToSNOW(t, username, password, requestURI, responseText)
	defer server.Close()

	snowUrl = server.URL

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)
	loggerObj.On("Debug", "InstallStatus: 1, CI name: app-demoapp")

	cmdb := p.getCI(username, password, ciName)
	assert.Equal(t, "1", cmdb.InstallStatus, "InstallStatus should be 1")
	assert.Equal(t, "app-demoapp", cmdb.Name, "Name should be app-demoapp")
}

func TestGetCITwoCIs(t *testing.T) {
	p, loggerObj := testGetP()
	responseText := "{\"result\":[{\"install_status\":\"1\", \"name\":\"app-demoapp\"},{\"install_status\":\"6\", \"name\":\"app-demoapp\"}]}"

	username := "testUser"
	password := "testPassword"
	ciName := "app-demoapp"
	requestURI := fmt.Sprintf("/api/now/table/cmdb_ci?name=%s&sysparm_fields=install_status,name", ciName)
	server := simulateHttpRequestToSNOW(t, username, password, requestURI, responseText)
	defer server.Close()

	snowUrl = server.URL

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)
	loggerObj.On("Debug", "InstallStatus: 1, CI name: app-demoapp")

	cmdb := p.getCI(username, password, ciName)
	assert.Equal(t, "1", cmdb.InstallStatus, "InstallStatus should be 1")
	assert.Equal(t, "app-demoapp", cmdb.Name, "Name should be app-demoapp")
}

func TestGetChangeServerDown(t *testing.T) {
	p, loggerObj := testGetP()
	errorText := "Service Now API server is down"
	responseText := "<html><body>Server down!</body></html>"

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			assert.Equal(t, errorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	username := "testUser"
	password := "testPassword"
	ciName := "app-demoapp"
	requestURI := fmt.Sprintf("/api/now/table/change_request?cmdb_ci=%s&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date&sysparm_limit=5&sysparm_offset=0", ciName)
	server := simulateHttpRequestToSNOW(t, username, password, requestURI, responseText)

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)
	loggerObj.On("Error", errorText)
	defer server.Close()

	snowUrl = server.URL

	_, _ = p.getChanges(username, password, "app-demoapp", 0)
}

func TestGetChangeNoJSON(t *testing.T) {
	p, loggerObj := testGetP()
	errorText := "Error in json.Unmarshal: invalid character '!' looking for beginning of value"
	responseText := "!"

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			assert.Equal(t, errorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	username := "testUser"
	password := "testPassword"
	ciName := "app-demoapp"
	requestURI := fmt.Sprintf("/api/now/table/change_request?cmdb_ci=%s&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date&sysparm_limit=5&sysparm_offset=0", ciName)
	server := simulateHttpRequestToSNOW(t, username, password, requestURI, responseText)
	defer server.Close()

	snowUrl = server.URL

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)
	loggerObj.On("Error", errorText)

	_, _ = p.getChanges(username, password, ciName, 0)
}

func TestGetChangeNoChange(t *testing.T) {
	p, loggerObj := testGetP()
	errorText := "No changes found"
	responseText := "{\"result\":[]}"

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			assert.Equal(t, errorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	username := "testUser"
	password := "testPassword"
	ciName := "app-demoapp"
	requestURI := fmt.Sprintf("/api/now/table/change_request?cmdb_ci=%s&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date&sysparm_limit=5&sysparm_offset=0", ciName)
	server := simulateHttpRequestToSNOW(t, username, password, requestURI, responseText)
	defer server.Close()

	snowUrl = server.URL

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)
	loggerObj.On("Error", errorText)

	_, _ = p.getChanges(username, password, ciName, 0)
}

func TestGetChangesOneChange(t *testing.T) {
	p, loggerObj := testGetP()
	responseText := `{"result":[{"type":"1", "number":"CHG300030", "short_description":"test", "start_date":"2025-05-15 17:00:00", "end_date":"2025-05-15 17:45:00"}]}`

	username := "testUser"
	password := "testPassword"
	ciName := "app-demoapp"
	requestURI := fmt.Sprintf("/api/now/table/change_request?cmdb_ci=%s&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date&sysparm_limit=5&sysparm_offset=0", ciName)
	server := simulateHttpRequestToSNOW(t, username, password, requestURI, responseText)
	defer server.Close()

	snowUrl = server.URL

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)

	changes, number := p.getChanges(username, password, ciName, 0)
	assert.Equal(t, "CHG300030", changes[0].Number, "Change number should be the same as in the API result")
	assert.Equal(t, 1, number, "Number should be incremented by the number of changes that are received")
	loggerObj.AssertExpectations(t)
}

func TestGetChangesTwoChanges(t *testing.T) {
	p, loggerObj := testGetP()
	responseText := `{"result":[{"type":"1", "number":"CHG300030", "short_description":"test", "start_date":"2025-05-15 17:00:00", "end_date":"2025-05-15 17:45:00"},
                                {"type":"1", "number":"CHG300031", "short_description":"test2", "start_date":"2025-05-15 18:00:00", "end_date":"2025-05-15 18:45:00"}]}`

	username := "testUser"
	password := "testPassword"
	ciName := "app-demoapp"
	requestURI := fmt.Sprintf("/api/now/table/change_request?cmdb_ci=%s&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date&sysparm_limit=5&sysparm_offset=0", ciName)
	server := simulateHttpRequestToSNOW(t, username, password, requestURI, responseText)
	defer server.Close()

	snowUrl = server.URL

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)

	changes, number := p.getChanges(username, password, ciName, 0)
	assert.Equal(t, "CHG300030", changes[0].Number, "Change number should be the same as in the API result")
	assert.Equal(t, 2, number, "Number should be incremented by the number of changes that are received")
	assert.Equal(t, "CHG300031", changes[1].Number, "Change number should be the same as in the API result")
	loggerObj.AssertExpectations(t)
}

func TestConvertTimeCorrectTime(t *testing.T) {
	p, loggerObj := testGetP()

	result := p.convertTime("2025-05-15 18:14:13")
	assert.Equal(t, 18, result.Hour(), "Hours match")
	assert.Equal(t, 14, result.Minute(), "Minutes match")
	assert.Equal(t, 13, result.Second(), "Seconds match")

	loggerObj.AssertExpectations(t)
}

func TestConvertTimeIncorrectTime(t *testing.T) {
	p, loggerObj := testGetP()
	timeString := "current"

	errorText := fmt.Sprintf("Error in converting %s to go Time: parsing time \"currentZ\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \"currentZ\" as \"2006\"", timeString)
	loggerObj.On("Error", errorText)

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			assert.Equal(t, errorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	_ = p.convertTime(timeString)
}

// func TestGetFromSNOWAPINoSnowURL(t *testing.T) {
// 	p, loggerObj := testGetP()

// 	errorText := "No Service Now URL given (environment variable SERVICE_NOW_URL is empty)"

// 	defer func() {
// 		if r := recover(); r != nil {
// 			fmt.Println("Recovered panic text:", r)
// 			assert.Equal(t, fmt.Sprintf("%v", r), errorText, "Panic text is correct")
// 		}
// 		loggerObj.AssertExpectations(t)
// 	}()

// 	loggerObj.On("Error", errorText)

// 	snowUrl = ""
// 	username := "user"
// 	password := "pwd"
// 	apiCall := "/api/test"
// 	_ = p.getFromSNOWAPI(username, password, apiCall)

// }
