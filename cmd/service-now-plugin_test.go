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

	batchv1 "k8s.io/api/batch/v1"
	coreV1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
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

type ServiceNowTestSuite struct {
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
	expectedErrorText := "Panic!"

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			s.Assertions.Equal(expectedErrorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	serviceNowUrl = ""
	os.Setenv("SERVICE_NOW_URL", "")
	loggerObj.On("Error", expectedErrorText)

	serviceNowUrl = p.getEnvVarWithPanic("SERVICE_NOW_URL", expectedErrorText)

	t.Errorf("The code did not panic")
}

func (s *HelperMethodsTestSuite) TestGetEnvVarWithPanicWithEnvVar() {
	t := s.T()

	p, loggerObj := testGetPlugin()

	serviceNowUrl = ""
	os.Setenv("SERVICE_NOW_URL", "https://example.com")

	serviceNowUrl = p.getEnvVarWithPanic("SERVICE_NOW_URL", "Panic!")

	s.Assertions.Equal("https://example.com", serviceNowUrl, "The correct URL is retrieved")
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

	currentTimeAmsterdamSummertimeString := fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d",
		currentTimeAmsterdamSummertime.Year(),
		currentTimeAmsterdamSummertime.Month(),
		currentTimeAmsterdamSummertime.Day(),
		currentTimeAmsterdamSummertime.Hour(),
		currentTimeAmsterdamSummertime.Minute(),
		currentTimeAmsterdamSummertime.Second())
	currentTimeAmsterdamWintertimeString := fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d",
		currentTimeAmsterdamWintertime.Year(),
		currentTimeAmsterdamWintertime.Month(),
		currentTimeAmsterdamWintertime.Day(),
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

	expectedErrorText := fmt.Sprintf("Error in converting %s to go Time: parsing time \"currentZ\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \"currentZ\" as \"2006\"", timeString)

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			s.Assertions.Equal(expectedErrorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	loggerObj.On("Error", expectedErrorText)
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

func (s *PluginHelperMethodsTestSuite) TestGetGlobalVars() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	exampleUrl := "https://example.com"
	os.Setenv("SERVICE_NOW_URL", exampleUrl)
	os.Setenv("TIMEZONE", "")
	os.Setenv("EXCLUSION_GROUPS", "")

	secretName := "servicenow-secret"
	namespace := "argocd-ephemeral-access"
	testUsername := "my-username"
	testPassword := "my-password"
	setCredentialsSecret(namespace, secretName, testUsername, testPassword)

	loggerObj.On("Debug", mock.Anything)

	unittest = true
	p.getGlobalVars()

	s.Assertions.Equal(exampleUrl, serviceNowUrl, "serviceNowUrl should be retrieved from environment variables")
	s.Assertions.Equal("UTC", timezone, "Default timezone should be UTC")
	s.Assertions.Equal(testUsername, serviceNowUsername, "ServiceNow username should be correct")
	s.Assertions.Equal(testPassword, serviceNowPassword, "ServiceNow password should be correct")
	s.Assertions.Equal([]string{""}, exclusionRoles, "Default for exclusion roles is empty")
	loggerObj.AssertExpectations(t)
}

func (s *PluginHelperMethodsTestSuite) TestGetGlobalVarsExclusionGroupsWithValue() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	exampleUrl := "https://example.com"
	os.Setenv("SERVICE_NOW_URL", exampleUrl)
	os.Setenv("EXCLUSION_ROLES", "incidentmanagers")

	secretName := "servicenow-secret"
	namespace := "argocd-ephemeral-access"
	testUsername := "my-username"
	testPassword := "my-password"
	setCredentialsSecret(namespace, secretName, testUsername, testPassword)

	loggerObj.On("Debug", mock.Anything)

	unittest = true
	p.getGlobalVars()

	s.Assertions.Equal([]string{"incidentmanagers"}, exclusionRoles, "Exclusion roles should be correct")
	loggerObj.AssertExpectations(t)
}

func (s *PluginHelperMethodsTestSuite) TestGetGlobalVarsExclusionRolesWithTwoValues() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	exampleUrl := "https://example.com"
	os.Setenv("SERVICE_NOW_URL", exampleUrl)
	os.Setenv("EXCLUSION_ROLES", "administrators,incidentmanagers")

	secretName := "servicenow-secret"
	namespace := "argocd-ephemeral-access"
	testUsername := "my-username"
	testPassword := "my-password"
	setCredentialsSecret(namespace, secretName, testUsername, testPassword)

	loggerObj.On("Debug", mock.Anything)

	unittest = true
	p.getGlobalVars()

	s.Assertions.Equal([]string{"administrators", "incidentmanagers"}, exclusionRoles, "Exclusion groups should be correct")
	loggerObj.AssertExpectations(t)
}

func TestK8SRelated(t *testing.T) {
	suite.Run(t, new(K8SRelatedTestSuite))
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

func testConvertTimeToString(t time.Time) string {
	return fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
}

func (s *PluginHelperMethodsTestSuite) TestCreateRevokeJobCorrect() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	namespace := "argocd"
	accessRequestName := "test-ar"
	jobStartTime := time.Now().Add(-1 * time.Minute)
	expectedJobName := "stop-" + accessRequestName

	k8sclientset = testclient.NewClientset()

	loggerObj.On("Debug", fmt.Sprintf("createRevokeJob: %s, %s", namespace, accessRequestName))
	loggerObj.On("Info", fmt.Sprintf("Created K8s job %s successfully in namespace argocd", expectedJobName))

	p.createRevokeJob(namespace, accessRequestName, jobStartTime)

	expectedSchedule := fmt.Sprintf("%d %d %d %d *", jobStartTime.Minute(), jobStartTime.Hour(), jobStartTime.Day(), jobStartTime.Month())
	expectedCommand := []string{"sh", "-c", fmt.Sprintf("kubectl delete accessrequest -n argocd %s && kubectl delete cronjob -n argocd %s", accessRequestName, expectedJobName)}
	cronjobs := k8sclientset.BatchV1().CronJobs(namespace)
	myCronJob, err := cronjobs.Get(context.TODO(), expectedJobName, metav1.GetOptions{})

	var zero int32 = 0

	s.Assertions.Equal(expectedJobName, myCronJob.ObjectMeta.Name, "Name should be the correct job name")
	s.Assertions.Equal(namespace, myCronJob.ObjectMeta.Namespace, "Namespace should be the correct namespace")
	s.Assertions.Equal(expectedSchedule, myCronJob.Spec.Schedule, "Schedule should be the correct schedule")
	s.Assertions.Equal("remove-accessrequest-job-sa", myCronJob.Spec.JobTemplate.Spec.Template.Spec.ServiceAccountName, "Service account name should be the correct service account name")
	s.Assertions.Equal(expectedJobName, myCronJob.Spec.JobTemplate.Spec.Template.Spec.Containers[0].Name, "Container name should be the correct container name")
	s.Assertions.Equal("bitnami/kubectl:latest", myCronJob.Spec.JobTemplate.Spec.Template.Spec.Containers[0].Image, "Image should be the correct image")
	s.Assertions.Equal(expectedCommand, myCronJob.Spec.JobTemplate.Spec.Template.Spec.Containers[0].Command, "Image should be the correct image")
	s.Assertions.Equal(v1.RestartPolicyNever, myCronJob.Spec.JobTemplate.Spec.Template.Spec.RestartPolicy, "Restart policy should be never")
	s.Assertions.Equal(&zero, myCronJob.Spec.JobTemplate.Spec.BackoffLimit, "BackoffLimit should be 0")

	s.Assertions.Equal(nil, err, "No errors expected")

	loggerObj.AssertExpectations(t)
	_ = cronjobs.Delete(context.TODO(), expectedJobName, metav1.DeleteOptions{})
}

func (s *PluginHelperMethodsTestSuite) TestCreateRevokeJobFail() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	namespace := "argocd"
	accessRequestName := "test-ar"
	jobStartTime := time.Now().Add(-1 * time.Minute)
	expectedJobName := "stop-" + accessRequestName

	k8sclientset = testclient.NewClientset()

	loggerObj.On("Debug", fmt.Sprintf("createRevokeJob: %s, %s", namespace, accessRequestName))
	loggerObj.On("Error", fmt.Sprintf("Failed to create K8s job %s in namespace argocd: cronjobs.batch \"stop-test-ar\" already exists.", expectedJobName))

	cronjobs := k8sclientset.BatchV1().CronJobs(namespace)
	cronJobSpec := &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:      expectedJobName,
			Namespace: namespace,
		},
	}
	_, _ = cronjobs.Create(context.TODO(), cronJobSpec, metav1.CreateOptions{})

	p.createRevokeJob(namespace, accessRequestName, jobStartTime)

	loggerObj.AssertExpectations(t)
	_ = cronjobs.Delete(context.TODO(), expectedJobName, metav1.DeleteOptions{})
}

func (s *PluginHelperMethodsTestSuite) TestDetermineDurationAndRealEndTimeChangeTimeWins() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	var arDuration time.Duration = 4 * time.Hour
	var changeRemainingTime time.Duration = 1 * time.Hour
	var endDate = time.Now().Add(1 * time.Hour)

	duration, realEndTime := p.determineDurationAndRealEndTime(arDuration, changeRemainingTime, endDate)

	s.Assertions.Equal(changeRemainingTime, duration, "Expected duration: 1 hour")
	s.Assertions.Equal(endDate, realEndTime, "Expected end time: 1 hour from now")

	loggerObj.AssertExpectations(t)
}

func (s *PluginHelperMethodsTestSuite) TestDetermineDurationAndRealEndTimeArDurationWins() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	var arDuration time.Duration = 4 * time.Hour
	var changeRemainingTime time.Duration = 8 * time.Hour
	var endDate = time.Now().Add(8 * time.Hour)

	var expectedRealEndTime = time.Now().Add(4 * time.Hour)

	duration, realEndTime := p.determineDurationAndRealEndTime(arDuration, changeRemainingTime, endDate)

	s.Assertions.Equal(arDuration, duration, "Expected duration: 4 hour")
	s.Assertions.Equal(expectedRealEndTime, realEndTime, "Expected end time: 4 hour from now")

	loggerObj.AssertExpectations(t)
}

func (s *PluginHelperMethodsTestSuite) TestDetermineGrantedTextsChange() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	requesterName := "TestUser"
	requestedRole := "admin"
	var validChange Change

	validChange.Type = "1"
	validChange.Number = "CHG300300"
	validChange.ShortDescription = "unittests"
	validChange.EndDate = time.Date(2025, 5, 20, 23, 59, 59, 0, time.UTC)
	realEndDate := time.Date(2025, 5, 20, 23, 59, 59, 0, time.UTC)

	var remainingTime time.Duration = 1 * time.Hour
	expectedGrantedAccessText := fmt.Sprintf("Granted access for %s: %s change %s (%s), role %s, from %s to %s",
		requesterName,
		validChange.Type,
		validChange.Number,
		validChange.ShortDescription,
		requestedRole,
		time.Now().Truncate(time.Minute),
		realEndDate.Truncate(time.Second).String())
	expectedGrantedAccessUIText := fmt.Sprintf("Granted access: change __%s__ (%s), until __%s (%s)__",
		validChange.Number,
		validChange.ShortDescription,
		p.getLocalTime(realEndDate),
		remainingTime.Truncate(time.Second).String())
	expectedGrantedAccessServiceNowText := fmt.Sprintf("ServiceNow plugin granted access to %s, for role %s, until %s (%s)",
		requesterName,
		requestedRole,
		p.getLocalTime(realEndDate),
		remainingTime.Truncate(time.Second).String())

	loggerObj.On("Info", expectedGrantedAccessText)
	loggerObj.On("Debug", expectedGrantedAccessUIText)

	grantedAccessUIText, grantedAccessServiceNowText := p.determineGrantedTextsChange(requesterName, requestedRole, validChange, remainingTime, realEndDate)

	s.Assertions.Equal(expectedGrantedAccessUIText, grantedAccessUIText, "Granted access text for UI should be what is expected")
	s.Assertions.Equal(expectedGrantedAccessServiceNowText, grantedAccessServiceNowText, "Granted access text for ServiceNow should be what is expected")

	loggerObj.AssertExpectations(t)
}

func (s *PluginHelperMethodsTestSuite) TestDetermineGrantedTextsExclusions() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	requesterName := "TestUser"
	requestedRole := "admin"

	var remainingTime time.Duration = 1 * time.Hour
	realEndDate := time.Now().Add(remainingTime)

	expectedGrantedAccessText := fmt.Sprintf("Granted access for %s: role %s, from %s to %s (no change, %s is an exclusion role)",
		requesterName,
		requestedRole,
		time.Now().Truncate(time.Minute),
		realEndDate.Truncate(time.Minute),
		requestedRole)
	expectedGrantedAccessUIText := fmt.Sprintf("Granted access: %s is an exclusion role, until __%s (%s)__",
		requestedRole,
		p.getLocalTime(realEndDate),
		remainingTime.Truncate(time.Second).String())

	loggerObj.On("Warn", expectedGrantedAccessText)
	loggerObj.On("Debug", expectedGrantedAccessUIText)

	grantedAccessUIText := p.determineGrantedTextsExclusions(requesterName, requestedRole, remainingTime, realEndDate)

	s.Assertions.Equal(expectedGrantedAccessUIText, grantedAccessUIText, "Granted access text for UI should be what is expected")
	loggerObj.AssertExpectations(t)
}

func (s *PluginHelperMethodsTestSuite) TestDenyRequest() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	reason := "whatever"
	response, err := p.denyRequest(reason)

	s.Assertions.Equal(plugin.GrantStatusDenied, response.Status, response, "Access request should be denied")
	s.Assertions.Equal(reason, response.Message, response, "Reason should be correct")
	s.Assertions.Equal(nil, err, "No error")

	loggerObj.AssertExpectations(t)
}

func (s *PluginHelperMethodsTestSuite) TestGrantRequest() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	reason := "whatever"
	response, err := p.grantRequest(reason)

	s.Assertions.Equal(plugin.GrantStatusGranted, response.Status, response, "Access request should be denied")
	s.Assertions.Equal(reason, response.Message, response, "Reason should be correct")
	s.Assertions.Equal(nil, err, "No error")

	loggerObj.AssertExpectations(t)
}

func setCredentialsSecret(namespace string, secretName string, username string, password string) {
	secret := &coreV1.Secret{
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
	k8sclientset.CoreV1().Secrets(namespace).Create(context.TODO(), secret, metav1.CreateOptions{})
}

func (s *PluginHelperMethodsTestSuite) TestGetServiceNowCredentials() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	secretName := "servicenow-secret"
	namespace := "argocd-ephemeral-access"
	serviceNowUsername := "serviceNowUsername"
	serviceNowPassword := "serviceNowPassword"

	setCredentialsSecret(namespace, secretName, serviceNowUsername, serviceNowPassword)

	loggerObj.On("Debug", "Environment variable SERVICENOW_SECRET_NAMESPACE is empty, assuming argocd-ephemeral-access")
	loggerObj.On("Debug", "Environment variable SERVICENOW_SECRET_NAME is empty, assuming servicenow-secret")
	loggerObj.On("Debug", "Get credentials from secret [argocd-ephemeral-access]servicenow-secret...")

	username, password := p.getServiceNowCredentials()

	s.Assertions.Equal(serviceNowUsername, username, "Username found")
	s.Assertions.Equal(serviceNowPassword, password, "Password found")

	loggerObj.AssertExpectations(t)
}

func TestPluginHelperMethods(t *testing.T) {
	suite.Run(t, new(PluginHelperMethodsTestSuite))
}

func simulateSimpleHttpRequestToServiceNow(t *testing.T, responseMap map[string]string) *httptest.Server {

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := ""
		for uri, _ := range responseMap {
			if uri == r.URL.RequestURI() {
				response = responseMap[uri]
				break
			}
		}
		if response == "" {
			fmt.Printf("No response found for %s, error in testset?\n", r.URL.RequestURI())
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("Expected Accept: application/json header, got: %s", r.Header.Get("Accept"))
		}
		usedUsername, usedPassword, ok := r.BasicAuth()
		if ok {
			assert.Equal(t, serviceNowUsername, usedUsername, "Username that is used should match username that is requested")
			assert.Equal(t, serviceNowPassword, usedPassword, "Password that is used should match username that is requested")
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(response))
	}))
	return server
}

func simulateSimpleHttpRequestWithStatusCodeRedirect(response string) (*httptest.Server, *httptest.Server) {

	var secondServer *httptest.Server = httptest.NewServer(http.HandlerFunc(func(w2 http.ResponseWriter, r2 *http.Request) {
		w2.WriteHeader(http.StatusOK)
		w2.Write([]byte(response))
	}))

	server := httptest.NewServer(http.HandlerFunc(func(w1 http.ResponseWriter, r1 *http.Request) {
		http.Redirect(w1, r1, secondServer.URL, http.StatusFound)
	}))
	return server, secondServer
}

func simulateSimpleHttpRequestWithStatusCodeForbidden(response string) *httptest.Server {

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(response))
	}))
	return server
}

func simulateSimpleHttpRequestWithStatusCodeServerSideError(response string) *httptest.Server {

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(response))
	}))
	return server
}

func (s *ServiceNowTestSuite) TestCheckAPIResultNormalResponse() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	var resp = http.Response{
		Status:     "200 OK",
		StatusCode: 200,
	}
	var body string = `{"result":[]}`

	result := p.checkAPIResult(&resp, []byte(body))

	s.Assertions.Equal(body, string(result), "Body should not be changed")
	loggerObj.AssertExpectations(t)
}

func (s *ServiceNowTestSuite) TestCheckAPIResultForbidden() {
	t := s.T()
	p, loggerObj := testGetPlugin()
	expectedErrorText := "ServiceNow API changed"

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			s.Assertions.Equal(expectedErrorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	var resp = http.Response{
		Status:     "403 Forbidden",
		StatusCode: 403,
	}
	var body string = `{"result":[]}`
	loggerObj.On("Error", expectedErrorText)

	_ = p.checkAPIResult(&resp, []byte(body))
}

func (s *ServiceNowTestSuite) TestCheckAPIResultBadGateway() {
	t := s.T()
	p, loggerObj := testGetPlugin()
	expectedErrorText := "ServiceNow API server is down"

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			s.Assertions.Equal(expectedErrorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	var resp = http.Response{
		Status:     "502 Bad Gateway",
		StatusCode: 502,
	}
	var body string = `{"result":[]}`
	loggerObj.On("Error", expectedErrorText)

	_ = p.checkAPIResult(&resp, []byte(body))
}

func (s *ServiceNowTestSuite) TestCheckAPIResultBadGatewayWith200() {
	t := s.T()
	p, loggerObj := testGetPlugin()
	expectedErrorText := "ServiceNow API server is down"

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			s.Assertions.Equal(expectedErrorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	var resp = http.Response{
		Status:     "200 OK",
		StatusCode: 200,
	}
	responseText := "<html><body>Server down!</body></html>"
	loggerObj.On("Error", expectedErrorText)

	_ = p.checkAPIResult(&resp, []byte(responseText))
}

func (s *ServiceNowTestSuite) TestGetFromServiceNowAPIErrorInApiCall() {
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

	serviceNowUsername = "testUser"
	serviceNowPassword = "testPassword"
	ciName := "app-demoapp"

	requestURI := fmt.Sprintf("/api/now/table/cmdb_ci?name=%s&sysparm_fields=install_status,name", ciName)

	var responseMap map[string]string = make(map[string]string)
	responseMap[requestURI] = responseText

	server := simulateSimpleHttpRequestToServiceNow(t, responseMap)
	defer server.Close()
	serviceNowUrl = server.URL

	// requestURI is changed to something incorrect (contains serviceNowUrl which it shouldn't)

	requestURI = fmt.Sprintf("%s%s", serviceNowUrl, requestURI)

	// Expected apiCall contains the serviceNowUrl twice
	apiCall := fmt.Sprintf("%s%s", serviceNowUrl, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Error", mock.Anything)

	_ = p.getFromServiceNowAPI(requestURI)
	loggerObj.AssertExpectations(t)
}

func (s *ServiceNowTestSuite) TestgetFromServiceNowAPIError() {
	t := s.T()
	p, loggerObj := testGetPlugin()
	expectedErrorText := "ServiceNow API server is down"
	responseText := "<html><body>Server down!</body></html>"

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			s.Assertions.Equal(expectedErrorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	serviceNowUsername = "testUser"
	serviceNowPassword = "testPassword"
	requestURI := "/api/test"

	var responseMap map[string]string = make(map[string]string)
	responseMap[requestURI] = responseText

	server := simulateSimpleHttpRequestToServiceNow(t, responseMap)
	defer server.Close()
	serviceNowUrl = server.URL

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)
	loggerObj.On("Error", expectedErrorText)

	_ = p.getFromServiceNowAPI(requestURI)
	loggerObj.AssertExpectations(t)
}

func (s *ServiceNowTestSuite) TestgetFromServiceNowAPINormalResponse() {
	t := s.T()
	p, loggerObj := testGetPlugin()
	responseText := "{\"results\":[]}"

	serviceNowUsername = "testUser"
	serviceNowPassword = "testPassword"
	requestURI := "/api/test"

	var responseMap map[string]string = make(map[string]string)
	responseMap[requestURI] = responseText

	server := simulateSimpleHttpRequestToServiceNow(t, responseMap)
	defer server.Close()
	serviceNowUrl = server.URL

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)

	result := p.getFromServiceNowAPI(requestURI)
	s.Assertions.Equal(responseText, string(result), "Correct result from API")
	loggerObj.AssertExpectations(t)
}

func (s *ServiceNowTestSuite) TestgetFromServiceNowAPINormalResponseWithRedirect() {
	t := s.T()
	p, loggerObj := testGetPlugin()
	responseText := "{\"results\":[]}"

	serviceNowUsername = "testUser"
	serviceNowPassword = "testPassword"
	requestURI := "/api/test"

	var responseMap map[string]string = make(map[string]string)
	responseMap[requestURI] = responseText

	server, secondServer := simulateSimpleHttpRequestWithStatusCodeRedirect(responseText)
	defer server.Close()
	defer secondServer.Close()
	serviceNowUrl = server.URL

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)
	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)

	// Redirect is done by http, not by the plugin program. We will therefore just get the apiCall for the primary address,
	// not for the redirect server.
	//
	// It is very important that redirects works.

	result := p.getFromServiceNowAPI(requestURI)
	s.Assertions.Equal(responseText, string(result), "Correct result from API")
	loggerObj.AssertExpectations(t)
}

// PostNote is a very simple method, so re-use the test for PatchServiceNowAPINormalRequest for both methods

func testPatchServiceNowAPINormalRequest(s *ServiceNowTestSuite, requestURI string, data string, responseText string) {
	t := s.T()
	p, loggerObj := testGetPlugin()

	var responseMap map[string]string = make(map[string]string)
	responseMap[requestURI] = responseText

	server := simulateSimpleHttpRequestToServiceNow(t, responseMap)
	defer server.Close()
	serviceNowUrl = server.URL

	apiCall := fmt.Sprintf("%s%s", serviceNowUrl, requestURI)
	loggerObj.On("Debug", "apiCall: "+apiCall)
	loggerObj.On("Debug", "Data: "+data)
	loggerObj.On("Debug", "Body: "+responseText)

	result := p.patchServiceNowAPI(requestURI, data)
	s.Assertions.Equal(responseText, string(result), "Correct result from API")
	loggerObj.AssertExpectations(t)
}

func (s *ServiceNowTestSuite) TestPatchServiceNowAPINormalRequest() {
	serviceNowUrl = "https://example.com"
	requestURI := "/api/test/1"
	data := `{"test": 1, "result": "success"}`
	responseText := `{"test": 1, "testText": "More results than the data that is sent", "result": "success"}`

	testPatchServiceNowAPINormalRequest(s, requestURI, data, responseText)
}

func (s *ServiceNowTestSuite) TestPatchServiceNowAPIErrorInApiCall() {
	t := s.T()
	p, loggerObj := testGetPlugin()

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

	serviceNowUrl = "https://example.com"
	// Incorrect requestURI containing the serviceNowUrl
	incorrectRequestURI := fmt.Sprintf("%s/api/test/1", serviceNowUrl)
	// Correct requestURI for simulation env
	requestURI := fmt.Sprintf("%s/api/test/1", serviceNowUrl)
	data := `{"test": 1, "result": "success"}`
	responseText := `{}`

	var responseMap map[string]string = make(map[string]string)
	responseMap[requestURI] = responseText

	apiCall := fmt.Sprintf("%s%s", serviceNowUrl, requestURI)
	loggerObj.On("Debug", "apiCall: "+apiCall)
	loggerObj.On("Debug", "Data: "+data)
	loggerObj.On("Error", mock.Anything)

	_ = p.patchServiceNowAPI(incorrectRequestURI, data)
}

func (s *K8SRelatedTestSuite) TestGetCINameEmpty() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	var app *argocd.Application = new(argocd.Application)
	var m map[string]string

	loggerObj.On("Debug", "Search for ci-name in the CMDB...")
	loggerObj.On("Debug", "ciLabel ci-name found: ")

	app.ObjectMeta.Labels = m
	ciLabel = "ci-name"
	ciName := p.getCIName(app)

	s.Assertions.Equal("", ciName, "No label found, assume empty string")
	loggerObj.AssertExpectations(t)
}

func (s *K8SRelatedTestSuite) TestGetCINameFilled() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	var app *argocd.Application = new(argocd.Application)
	var m map[string]string = make(map[string]string)

	loggerObj.On("Debug", "Search for ci-name in the CMDB...")
	loggerObj.On("Debug", "ciLabel ci-name found: app-demoapp")

	ciLabel = "ci-name"
	m[ciLabel] = "app-demoapp"
	app.ObjectMeta.Labels = m

	ciLabel := p.getCIName(app)

	s.Assertions.Equal("app-demoapp", ciLabel, "Label found, content app-demoapp")
	loggerObj.AssertExpectations(t)
}

func (s *ServiceNowTestSuite) TestGetCIServerDown() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	expectedErrorText := "ServiceNow API server is down"
	responseText := "<html><body>Server down!</body></html>"

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			s.Assertions.Equal(expectedErrorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	serviceNowUsername = "testUser"
	serviceNowPassword = "testPassword"
	ciName := "app-demoapp"
	requestURI := fmt.Sprintf("/api/now/table/cmdb_ci?name=%s&sysparm_fields=install_status,name", ciName)

	var responseMap map[string]string = make(map[string]string)
	responseMap[requestURI] = responseText

	server := simulateSimpleHttpRequestToServiceNow(t, responseMap)
	defer server.Close()

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)
	loggerObj.On("Error", expectedErrorText)
	defer server.Close()

	serviceNowUrl = server.URL

	_ = p.getCI("app-demoapp")
}

func (s *ServiceNowTestSuite) TestGetCINoJSON() {
	t := s.T()
	p, loggerObj := testGetPlugin()
	expectedErrorText := "Error in json.Unmarshal: invalid character '<' looking for beginning of value (<Result/>)"
	responseText := "<Result/>"

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			s.Assertions.Equal(expectedErrorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	serviceNowUsername = "testUser"
	serviceNowPassword = "testPassword"
	ciName := "app-demoapp"
	requestURI := fmt.Sprintf("/api/now/table/cmdb_ci?name=%s&sysparm_fields=install_status,name", ciName)

	var responseMap map[string]string = make(map[string]string)
	responseMap[requestURI] = responseText

	server := simulateSimpleHttpRequestToServiceNow(t, responseMap)
	defer server.Close()

	serviceNowUrl = server.URL

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)
	loggerObj.On("Error", expectedErrorText)

	_ = p.getCI(ciName)
}

func (s *ServiceNowTestSuite) TestGetChangeServerDown() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	responseText := "<html><body>Server down!</body></html>"
	expectedErrorText := "ServiceNow API server is down"

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			s.Assertions.Equal(expectedErrorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	serviceNowUsername = "testUser"
	serviceNowPassword = "testPassword"
	ciName := "app-demoapp"
	requestURI := fmt.Sprintf("/api/now/table/change_request?cmdb_ci=%s&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date,sys_id&sysparm_limit=5&sysparm_offset=0", ciName)

	var responseMap map[string]string = make(map[string]string)
	responseMap[requestURI] = responseText

	server := simulateSimpleHttpRequestToServiceNow(t, responseMap)
	defer server.Close()

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)
	loggerObj.On("Error", expectedErrorText)
	defer server.Close()

	serviceNowUrl = server.URL

	_, _ = p.getChanges("app-demoapp", 0)
	loggerObj.AssertExpectations(t)
}

func (s *ServiceNowTestSuite) TestGetChangeNoJSON() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	responseText := "!"
	expectedErrorText := "Error in json.Unmarshal: invalid character '!' looking for beginning of value (!)"

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			s.Assertions.Equal(expectedErrorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	serviceNowUsername = "testUser"
	serviceNowPassword = "testPassword"
	ciName := "app-demoapp"
	requestURI := fmt.Sprintf("/api/now/table/change_request?cmdb_ci=%s&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date,sys_id&sysparm_limit=5&sysparm_offset=0", ciName)

	var responseMap map[string]string = make(map[string]string)
	responseMap[requestURI] = responseText

	server := simulateSimpleHttpRequestToServiceNow(t, responseMap)
	defer server.Close()

	serviceNowUrl = server.URL

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)
	loggerObj.On("Error", expectedErrorText)

	_, _ = p.getChanges(ciName, 0)
	loggerObj.AssertExpectations(t)
}

func TestServiceNowMethods(t *testing.T) {
	suite.Run(t, new(ServiceNowTestSuite))
}

func (s *CITestSuite) TestGetCINoCI() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	responseText := "{\"result\":[]}"
	expectedErrorText := "No CI with name app-demoapp found"

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered panic text:", r)
			s.Assertions.Equal(expectedErrorText, fmt.Sprintf("%v", r), "Panic text is correct")
		}
		loggerObj.AssertExpectations(t)
	}()

	serviceNowUsername = "testUser"
	serviceNowPassword = "testPassword"
	ciName := "app-demoapp"
	requestURI := fmt.Sprintf("/api/now/table/cmdb_ci?name=%s&sysparm_fields=install_status,name", ciName)

	var responseMap map[string]string = make(map[string]string)
	responseMap[requestURI] = responseText

	server := simulateSimpleHttpRequestToServiceNow(t, responseMap)
	defer server.Close()

	serviceNowUrl = server.URL
	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)
	loggerObj.On("Error", expectedErrorText)

	_ = p.getCI(ciName)
	loggerObj.AssertExpectations(t)
}

func testPrepareGetCI(t *testing.T, loggerObj *MockedLogger, ciName string, responseText string) (*httptest.Server, string) {
	serviceNowUsername = "testUser"
	serviceNowPassword = "testPassword"
	requestURI := fmt.Sprintf("/api/now/table/cmdb_ci?name=%s&sysparm_fields=install_status,name", ciName)

	var responseMap map[string]string = make(map[string]string)
	responseMap[requestURI] = responseText

	server := simulateSimpleHttpRequestToServiceNow(t, responseMap)
	serviceNowUrl = server.URL

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

	serviceNowUsername = "testUser"
	serviceNowPassword = "testPassword"
	ciName := "app-demoapp"
	requestURI := fmt.Sprintf("/api/now/table/change_request?cmdb_ci=%s&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date,sys_id&sysparm_limit=5&sysparm_offset=0", ciName)

	var responseMap map[string]string = make(map[string]string)
	responseMap[requestURI] = responseText

	server := simulateSimpleHttpRequestToServiceNow(t, responseMap)
	defer server.Close()

	serviceNowUrl = server.URL

	apiCall := fmt.Sprintf("%s%s", server.URL, requestURI)

	loggerObj.On("Debug", fmt.Sprintf("apiCall: %s", apiCall))
	loggerObj.On("Debug", responseText)
	loggerObj.On("Info", "No changes found")

	changes, newPointer := p.getChanges(ciName, 0)

	s.Assertions.Equal(0, len(changes), "No changes should be found")
	s.Assertions.Equal(0, newPointer, "New value for offset should be 0")
}

func testPrepareGetChange(t *testing.T, loggerObj *MockedLogger, ciName string, responseMap map[string]string) *httptest.Server {
	serviceNowUsername = "testUser"
	serviceNowPassword = "testPassword"

	server := simulateSimpleHttpRequestToServiceNow(t, responseMap)
	serviceNowUrl = server.URL

	return server
}

func (s *ChangeTestSuite) TestGetChangesOneChange() {
	t := s.T()

	p, loggerObj := testGetPlugin()

	ciName := "app-demoapp"
	responseText := `{"result":[{"type":"1", "number":"CHG300030", "short_description":"test", "start_date":"2025-05-15 17:00:00", "end_date":"2025-05-15 17:45:00"}]}`
	requestURI := fmt.Sprintf("/api/now/table/change_request?cmdb_ci=%s&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date,sys_id&sysparm_limit=5&sysparm_offset=0", ciName)

	var responseMap map[string]string = make(map[string]string)
	responseMap[requestURI] = responseText

	server := testPrepareGetChange(t, loggerObj, ciName, responseMap)
	defer server.Close()
	serviceNowUrl = server.URL

	apiCall := fmt.Sprintf("%s%s", serviceNowUrl, requestURI)
	loggerObj.On("Debug", "apiCall: "+apiCall)
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
	requestURI := fmt.Sprintf("/api/now/table/change_request?cmdb_ci=%s&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date,sys_id&sysparm_limit=5&sysparm_offset=0", ciName)
	responseText := `{"result":[{"type":"1", "number":"CHG300030", "short_description":"test", "start_date":"2025-05-15 17:00:00", "end_date":"2025-05-15 17:45:00"},
                                {"type":"1", "number":"CHG300031", "short_description":"test2", "start_date":"2025-05-15 18:00:00", "end_date":"2025-05-15 18:45:00"}]}`

	var responseMap map[string]string = make(map[string]string)
	responseMap[requestURI] = responseText

	server := testPrepareGetChange(t, loggerObj, ciName, responseMap)
	defer server.Close()
	serviceNowUrl = server.URL

	apiCall := fmt.Sprintf("%s%s", serviceNowUrl, requestURI)
	loggerObj.On("Debug", "apiCall: "+apiCall)
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
	requestURI := fmt.Sprintf("/api/now/table/change_request?cmdb_ci=%s&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date,sys_id&sysparm_limit=5&sysparm_offset=0", ciName)
	responseText := `{"result":[{"type":"1", "number":"CHG300030", "short_description":"test", "start_date":"2025-05-15 17:00:00", "end_date":"2025-05-15 17:45:00"},
                                {"type":"1", "number":"CHG300031", "short_description":"test2", "start_date":"2025-05-15 18:00:00", "end_date":"2025-05-15 18:45:00"},
                                {"type":"1", "number":"CHG300032", "short_description":"test3", "start_date":"2025-05-15 19:00:00", "end_date":"2025-05-15 19:45:00"},
                                {"type":"1", "number":"CHG300033", "short_description":"test4", "start_date":"2025-05-15 20:00:00", "end_date":"2025-05-15 20:45:00"},
                                {"type":"1", "number":"CHG300034", "short_description":"test5", "start_date":"2025-05-15 21:00:00", "end_date":"2025-05-15 21:45:00"}]}`

	var responseMap map[string]string = make(map[string]string)
	responseMap[requestURI] = responseText

	server := testPrepareGetChange(t, loggerObj, ciName, responseMap)
	defer server.Close()

	serviceNowUrl = server.URL

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

	var change_servicenow = ChangeServiceNow{
		Type:             "1",
		Number:           "CHG12345",
		EndDate:          "2025-05-16 23:59:59",
		ShortDescription: "Test",
		StartDate:        "2025-05-16 08:00:00",
		SysId:            "sys_id",
	}

	loggerObj.On("Debug", fmt.Sprintf("Change: Type: %s, Number: %s, Short description: %s, Start Date: %s, End Date: %s, SysId: %s",
		change_servicenow.Type,
		change_servicenow.Number,
		change_servicenow.ShortDescription,
		change_servicenow.StartDate,
		change_servicenow.EndDate,
		change_servicenow.SysId))

	chg := p.parseChange(change_servicenow)

	s.Assertions.Equal(change_servicenow.Type, chg.Type, "Change type should be the same")
	s.Assertions.Equal(change_servicenow.Number, chg.Number, "Change number should be the same")
	s.Assertions.Equal(time.Date(2025, 05, 16, 23, 59, 59, 0, time.UTC), chg.EndDate, "Change end date should be the same")
	s.Assertions.Equal(change_servicenow.ShortDescription, chg.ShortDescription, "Change short description should be the same")
	s.Assertions.Equal(time.Date(2025, 05, 16, 8, 0, 0, 0, time.UTC), chg.StartDate, "Change start date should be the same")
	s.Assertions.Equal(change_servicenow.SysId, chg.SysId, "Change sys_id should be the same")

	loggerObj.AssertExpectations(t)
}

func TestChangeMethods(t *testing.T) {
	suite.Run(t, new(ChangeTestSuite))
}

func testAllowedCIStatus(s *CheckCITestSuite, status string) {
	t := s.T()
	p, loggerObj := testGetPlugin()

	var ci = CmdbServiceNow{
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

	var ci = CmdbServiceNow{
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

	var change = Change{
		Type:             "1",
		Number:           "CHG12345",
		EndDate:          endDate,
		ShortDescription: "Test",
		StartDate:        startDate,
		SysId:            "1",
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

	var change = Change{
		Type:             "1",
		Number:           "CHG12345",
		EndDate:          endDate,
		ShortDescription: "Test",
		StartDate:        startDate,
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

func (s *PluginHelperMethodsTestSuite) TestProcessCI() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	ciName := "app-demoapp"
	responseText := fmt.Sprintf(`{"result":[{"install_status":"1", "name":"%s"}]}`, ciName)
	server, _ := testPrepareGetCI(t, loggerObj, ciName, responseText)
	defer server.Close()
	serviceNowUrl = server.URL

	loggerObj.On("Debug", mock.Anything)

	errorString := p.processCI(ciName)

	s.Assertions.Equal("", errorString, "Errorstring should be empty")

	loggerObj.AssertExpectations(t)
}

func (s *PluginHelperMethodsTestSuite) TestProcessChanges() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	timezone = "UTC"
	currentTime := time.Now()
	startDate := currentTime.Add(-5 * time.Minute)
	endDate := currentTime.Add(time.Hour * 2)

	ciName := "app-demoapp"
	requestURI := fmt.Sprintf("/api/now/table/change_request?cmdb_ci=%s&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date,sys_id&sysparm_limit=5&sysparm_offset=0", ciName)
	responseText := fmt.Sprintf(`{"result":[{"type":"1", "number":"CHG300030", "short_description":"test", "start_date":"%s", "end_date":"%s"}]}`,
		testConvertTimeToString(startDate),
		testConvertTimeToString(endDate))

	var responseMap map[string]string = make(map[string]string)
	responseMap[requestURI] = responseText

	server := testPrepareGetChange(t, loggerObj, ciName, responseMap)
	defer server.Close()
	serviceNowUrl = server.URL

	loggerObj.On("Debug", mock.Anything)

	errorString, changeRemainingTime, validChange := p.processChanges(ciName)

	s.Assertions.Equal("", errorString, "Errorstring should be empty")
	if changeRemainingTime.Minutes() < 40 {
		s.Fail("changeRemainingTime is too small, less than 40 minutes")
	}

	s.Assertions.Equal("CHG300030", validChange.Number, "Numbers must be equal")
	s.Assertions.Equal("test", validChange.ShortDescription, "Short descriptions must be equal")
	loggerObj.AssertExpectations(t)
}

func (s *PluginHelperMethodsTestSuite) TestProcessChangesTwoWindows() {
	t := s.T()
	p, loggerObj := testGetPlugin()

	timezone = "UTC"
	currentTime := time.Now()
	startDate := currentTime.Add(-5 * time.Minute)
	endDate := currentTime.Add(time.Hour * 2)

	ciName := "app-demoapp"
	var responseMap map[string]string = make(map[string]string)

	requestURI := "/api/now/table/change_request?cmdb_ci=app-demoapp&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date,sys_id&sysparm_limit=5&sysparm_offset=0"
	responseText := `{"result":[{"type":"1", "number":"CHG300030", "short_description":"test", "start_date":"2025-05-15 17:00:00", "end_date":"2025-05-15 17:45:00"},
                                {"type":"1", "number":"CHG300031", "short_description":"test2", "start_date":"2025-05-15 18:00:00", "end_date":"2025-05-15 18:45:00"},
                                {"type":"1", "number":"CHG300032", "short_description":"test3", "start_date":"2025-05-15 19:00:00", "end_date":"2025-05-15 19:45:00"},
                                {"type":"1", "number":"CHG300033", "short_description":"test4", "start_date":"2025-05-15 20:00:00", "end_date":"2025-05-15 20:45:00"},
                                {"type":"1", "number":"CHG300034", "short_description":"test5", "start_date":"2025-05-15 21:00:00", "end_date":"2025-05-15 21:45:00"}]}`

	responseMap[requestURI] = responseText

	requestURI = "/api/now/table/change_request?cmdb_ci=app-demoapp&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date,sys_id&sysparm_limit=5&sysparm_offset=5"
	responseText = fmt.Sprintf(`{"result":[{"type":"1", "number":"CHG300040", "short_description":"test6", "start_date":"2025-05-15 17:00:00", "end_date":"2025-05-15 17:45:00"},
                                {"type":"1", "number":"CHG300041", "short_description":"test7", "start_date":"2025-05-15 18:00:00", "end_date":"2025-05-15 18:45:00"},
                                {"type":"1", "number":"CHG300042", "short_description":"test8", "start_date":"2025-05-15 19:00:00", "end_date":"2025-05-15 19:45:00"},
                                {"type":"1", "number":"CHG300043", "short_description":"test9", "start_date":"2025-05-15 20:00:00", "end_date":"2025-05-15 20:45:00"},
                                {"type":"1", "number":"CHG300044", "short_description":"test10", "start_date":"%s", "end_date":"%s"}]}`,
		testConvertTimeToString(startDate),
		testConvertTimeToString(endDate))

	responseMap[requestURI] = responseText

	server := testPrepareGetChange(t, loggerObj, ciName, responseMap)
	defer server.Close()
	serviceNowUrl = server.URL

	loggerObj.On("Debug", mock.Anything)

	errorString, changeRemainingTime, validChange := p.processChanges(ciName)

	s.Assertions.Equal("", errorString, "Errorstring should be empty")
	if changeRemainingTime.Minutes() < 40 {
		s.Fail("changeRemainingTime is too small, less than 40 minutes")
	}

	s.Assertions.Equal("CHG300044", validChange.Number, "Numbers must be equal")
	s.Assertions.Equal("test10", validChange.ShortDescription, "Short descriptions must be equal")
	loggerObj.AssertExpectations(t)
}

func simulateGlobalHttpRequestToServiceNow(startDateString string, endDateString string, installStatus string) *httptest.Server {

	var response string

	time.Local = time.UTC
	timezone = "UTC"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RequestURI() == "/api/now/table/cmdb_ci?name=app-demoapp&sysparm_fields=install_status,name" {
			response = fmt.Sprintf(`{"result": [{"install_status": "%s", "name": "demoapp"}]}`, installStatus)
		}
		if r.URL.RequestURI() == "/api/now/table/change_request?cmdb_ci=app-demoapp&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date,sys_id&sysparm_limit=5&sysparm_offset=0" {
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
	m["ci-name"] = "app-demoapp"
	app.ObjectMeta.Labels = m

	return ar, app
}

func (s *ServiceNowTestSuite) TestPostNote() {
	serviceNowUrl = "https://servicenow.com"
	requestURI := "/api/now/table/change_request/CHG0030002"
	noteText := `{"work_notes": "This is the text of the note"}`
	responseText := `{"number": "CHG00300002", "other_fields": "whatever"}`

	testPatchServiceNowAPINormalRequest(s, requestURI, noteText, responseText)
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

	os.Setenv("EXCLUSION_ROLES", "")
	os.Setenv("TIMEZONE", "UTC")
	currentTime := time.Now()
	startDate := currentTime.Add(-5 * time.Minute)
	endDate := currentTime.Add(2 * time.Hour)
	startDateString := fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", startDate.Year(), startDate.Month(), startDate.Day(), startDate.Hour(), startDate.Minute(), startDate.Second())
	endDateString := fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", endDate.Year(), endDate.Month(), endDate.Day(), endDate.Hour(), endDate.Minute(), endDate.Second())

	loggerObj.On("Debug", mock.Anything)
	loggerObj.On("Info", mock.Anything)

	var responseMap map[string]string = make(map[string]string)

	requestURI := "/api/now/table/cmdb_ci?name=app-demoapp&sysparm_fields=install_status,name"
	responseText := `{"result": [{"install_status": "1", "name": "demoapp"}]}`
	responseMap[requestURI] = responseText

	requestURI = "/api/now/table/change_request?cmdb_ci=app-demoapp&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date,sys_id&sysparm_limit=5&sysparm_offset=0"
	responseText = fmt.Sprintf(`{"result":[{"type":"1", "number":"CHG300030", "short_description":"valid change", "start_date":"%s", "end_date":"%s", "sys_id":"1"}]}`, startDateString, endDateString)
	responseMap[requestURI] = responseText

	requestURI = "/api/now/table/change_request/1" // for post, but whatever. We don't do anything with the response...
	responseText = `{"whatever":"true"}`
	responseMap[requestURI] = responseText

	server := simulateSimpleHttpRequestToServiceNow(t, responseMap)
	defer server.Close()

	os.Setenv("SERVICE_NOW_URL", server.URL)

	secretName := "servicenow-secret"
	namespace := "argocd-ephemeral-access"
	genericUsername := "serviceNowUsername"
	genericPassword := "serviceNowPassword"

	setCredentialsSecret(namespace, secretName, genericUsername, genericPassword)

	response, err := p.GrantAccess(&ar, &app)

	s.Assertions.Equal(plugin.GrantStatusGranted, response.Status, "Status should be granted")
	s.Assertions.Equal(nil, err, "Error should be nil")
	if !strings.Contains(response.Message, "Granted access") {
		t.Errorf("%s should contain text Granted access", response.Message)
	}
	loggerObj.AssertExpectations(t)
}

func (s *PublicMethodsTestSuite) TestGrantAccessExclusionRole() {
	t := s.T()

	p, loggerObj := testGetPlugin()

	unittest = true // don't initialize k8sconfig/k8sclientset

	ar, app := testGetArApp()

	os.Setenv("TIMEZONE", "UTC")
	loggerObj.On("Debug", mock.Anything)
	loggerObj.On("Info", mock.Anything)
	loggerObj.On("Warn", mock.Anything)

	os.Setenv("EXCLUSION_ROLES", "incidentmanagers")
	ar.Spec.Role.TemplateRef.Name = "incidentmanagers"

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

	errorText := "No CI name found: expected label with name ci-name in application demoapp"

	ar, app := testGetArApp()
	var m map[string]string = make(map[string]string)
	m["ci-name"] = "\"\""
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
	server := simulateGlobalHttpRequestToServiceNow(startDateString, endDateString, installStatus)
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
	server := simulateGlobalHttpRequestToServiceNow(startDateString, endDateString, installStatus)
	defer server.Close()
	os.Setenv("SERVICE_NOW_URL", server.URL)

	loggerObj.On("Debug", mock.Anything)
	loggerObj.On("Info", mock.Anything)
	loggerObj.On("Error", mock.Anything)
	response, err := p.GrantAccess(&ar, &app)

	containsCorrectText := strings.Contains(response.Message, "is not in the valid time range. start date: 2025-01-01 00:00:00 and end date: 2025-01-01 23:59:59")
	if !containsCorrectText {
		s.Assertions.Fail("Response message should be correct, is now: " + response.Message)
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
