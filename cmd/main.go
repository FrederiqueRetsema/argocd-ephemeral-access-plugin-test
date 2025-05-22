package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"encoding/json"
	"net/http"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	argocd "github.com/argoproj-labs/argocd-ephemeral-access/api/argoproj/v1alpha1"
	api "github.com/argoproj-labs/argocd-ephemeral-access/api/ephemeral-access/v1alpha1"
	"github.com/hashicorp/go-hclog"

	"github.com/argoproj-labs/argocd-ephemeral-access/pkg/log"
	"github.com/argoproj-labs/argocd-ephemeral-access/pkg/plugin"
	goPlugin "github.com/hashicorp/go-plugin"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ServiceNowPlugin struct {
	Logger hclog.Logger
}

type cmdb_servicenow_type struct {
	InstallStatus string `json:"install_status"`
	Name          string `json:"name"`
}

type cmdb_results_service_now_type struct {
	Result []*cmdb_servicenow_type `json:"result"`
}

type change_servicenow_type struct {
	Type             string `json:"type"`
	Number           string `json:"number"`
	EndDate          string `json:"end_date"`
	ShortDescription string `json:"short_description"`
	StartDate        string `json:"start_date"`
	SysId            string `json:"sys_id"`
}

type change_type struct {
	Type             string
	Number           string
	EndDate          time.Time
	ShortDescription string
	StartDate        time.Time
	SysId            string
}

type change_results_servicenow_type struct {
	Result []*change_servicenow_type `json:"result"`
}

const sysparm_limit = 5

var unittest = false

var serviceNowUrl string
var serviceNowUsername string
var serviceNowPassword string
var ciLabel string
var timezone string
var k8sconfig *rest.Config
var k8sclientset kubernetes.Interface

func (p *ServiceNowPlugin) getEnvVarWithPanic(envVarName string, panicText string) string {
	returnValue := os.Getenv(envVarName)
	if returnValue == "" {
		p.Logger.Error(panicText)
		panic(errors.New(panicText))
	}
	return returnValue
}

func (p *ServiceNowPlugin) getEnvVarWithDefault(envVarName string, envVarDefault string) string {
	returnValue := os.Getenv(envVarName)
	if returnValue == "" {
		p.Logger.Debug(fmt.Sprintf("Environment variable %s is empty, assuming %s", envVarName, envVarDefault))
		returnValue = envVarDefault
	}
	return returnValue
}

func (p *ServiceNowPlugin) getLocalTime(t time.Time) string {
	loc, _ := time.LoadLocation(timezone)

	return fmt.Sprintf("%02d:%02d:%02d",
		t.In(loc).Hour(),
		t.In(loc).Minute(),
		t.In(loc).Second())
}

func (p *ServiceNowPlugin) convertTime(timestring string) time.Time {
	goTimeString := strings.Replace(timestring, " ", "T", -1) + "Z"

	var goTime time.Time
	err := goTime.UnmarshalText([]byte(goTimeString))
	if err != nil {
		errorText := "Error in converting " + timestring + " to go Time: " + err.Error()
		p.Logger.Error(errorText)
		panic(errorText)
	}
	return goTime
}

func (p *ServiceNowPlugin) getK8sConfig() {
	var err error

	if !unittest {
		k8sconfig, err = rest.InClusterConfig()
		if err != nil {
			panic(err.Error())
		}

		k8sclientset, err = kubernetes.NewForConfig(k8sconfig)
		if err != nil {
			panic(err.Error())
		}
	}
}

func (p *ServiceNowPlugin) getCredentialsFromSecret(namespace string, secretName string, usernameKey string, passwordKey string) (string, string) {
	p.Logger.Debug(fmt.Sprintf("Get credentials from secret [%s]%s...", namespace, secretName))

	secret, err := k8sclientset.CoreV1().Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
	if err != nil {
		p.Logger.Error(fmt.Sprintf("Error getting secret %s, does secret exist in namespace %s?", secretName, namespace))
		panic(err.Error())
	}

	return string(secret.Data[usernameKey]), string(secret.Data[passwordKey])
}

func (p *ServiceNowPlugin) getCIName(app *argocd.Application) string {
	p.Logger.Debug("Search for " + ciLabel + " in the CMDB...")
	ciName := string(app.ObjectMeta.Labels[ciLabel])
	p.Logger.Debug(fmt.Sprintf("ciLabel %s found: %s", ciLabel, ciName))

	return ciName
}

func (p *ServiceNowPlugin) showRequest(ar *api.AccessRequest, app *argocd.Application) {
	username := ar.Spec.Subject.Username
	role := ar.Spec.Role.TemplateRef.Name
	namespace := ar.Spec.Application.Namespace
	applicationName := ar.Spec.Application.Name
	duration := ar.Spec.Duration.Duration.String()

	infoText := fmt.Sprintf("Call to GrantAccess: username: %s, role: %s, application: [%s]%s, duration: %s", username, role, namespace, applicationName, duration)
	p.Logger.Info(infoText)

	jsonAr, _ := json.Marshal(ar)
	jsonApp, _ := json.Marshal(app)
	p.Logger.Debug("jsonAr: " + string(jsonAr))
	p.Logger.Debug("jsonApp: " + string(jsonApp))
}

func (p *ServiceNowPlugin) createRevokeJob(namespace string, accessrequestName string, jobStartTime time.Time) {
	p.Logger.Debug(fmt.Sprintf("createRevokeJob: %s, %s", namespace, accessrequestName))
	jobName := strings.Replace("stop-"+accessrequestName, ".", "-", -1)
	cmd := fmt.Sprintf("kubectl delete accessrequest -n argocd %s && kubectl delete cronjob -n argocd %s", accessrequestName, jobName)
	cronjobs := k8sclientset.BatchV1().CronJobs(namespace)

	var backOffLimit int32 = 0

	cronJobSpec := &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: namespace,
		},
		Spec: batchv1.CronJobSpec{
			Schedule: fmt.Sprintf("%d %d %d %d *", jobStartTime.Minute(), jobStartTime.Hour(), jobStartTime.Day(), jobStartTime.Month()),
			JobTemplate: batchv1.JobTemplateSpec{
				Spec: batchv1.JobSpec{
					Template: v1.PodTemplateSpec{
						Spec: v1.PodSpec{
							ServiceAccountName: "remove-accessrequest-job-sa",
							Containers: []v1.Container{
								{
									Name:    jobName,
									Image:   "bitnami/kubectl:latest",
									Command: []string{"sh", "-c", cmd},
								},
							},
							RestartPolicy: v1.RestartPolicyNever,
						},
					},
					BackoffLimit: &backOffLimit,
				},
			},
		},
	}

	_, err := cronjobs.Create(context.TODO(), cronJobSpec, metav1.CreateOptions{})
	if err != nil {
		p.Logger.Error(fmt.Sprintf("Failed to create K8s job %s in namespace %s: %s.", jobName, namespace, err.Error()))
	} else {
		p.Logger.Info(fmt.Sprintf("Created K8s job %s successfully in namespace %s", jobName, namespace))
	}
}

// Set duration to the time left for this (valid) change, unless original request was
// shorter - then we are forced to use the duration of the original request.
// In an ideal world, the enddate should always be the enddate of the change and the duration always the amount of time
// that remains until that moment.

func (p *ServiceNowPlugin) determineDurationAndRealEndTime(arDuration time.Duration, changeRemainingTime time.Duration, changeEndDate time.Time) (time.Duration, time.Time) {
	var duration time.Duration
	var realEndTime time.Time

	if arDuration > changeRemainingTime {
		duration = changeRemainingTime
		realEndTime = changeEndDate
	} else {
		duration = arDuration
		realEndTime = time.Now().Add(arDuration)
	}

	return duration, realEndTime
}

func (p *ServiceNowPlugin) determineGrantedTexts(requesterName string, requestedRole string, validChange change_type, remainingTime time.Duration, realEndDate time.Time) (string, string, string) {

	grantedAccessText := fmt.Sprintf("Granted access for %s: %s change %s (%s), role %s, from %s to %s",
		requesterName,
		validChange.Type,
		validChange.Number,
		validChange.ShortDescription,
		requestedRole,
		p.getLocalTime(time.Now()),
		p.getLocalTime(validChange.EndDate))

	grantedAccessUIText := fmt.Sprintf("Granted access: change __%s__ (%s), until __%s (%s)__",
		validChange.Number,
		validChange.ShortDescription,
		realEndDate,
		remainingTime.Truncate(time.Second).String())

	grantedAccessServiceNowText := fmt.Sprintf("Granted access: to %s, for role %s, until %s (%s)",
		requesterName,
		requestedRole,
		realEndDate,
		remainingTime.Truncate(time.Second).String())

	return grantedAccessText, grantedAccessUIText, grantedAccessServiceNowText
}

func (p *ServiceNowPlugin) deny(reason string) (*plugin.GrantResponse, error) {
	return &plugin.GrantResponse{
		Status:  plugin.GrantStatusDenied,
		Message: reason,
	}, nil
}

func (p *ServiceNowPlugin) grant(reason string) (*plugin.GrantResponse, error) {
	return &plugin.GrantResponse{
		Status:  plugin.GrantStatusGranted,
		Message: reason,
	}, nil
}

func (p *ServiceNowPlugin) getServiceNowCredentials() (string, string) {
	namespace := p.getEnvVarWithDefault("SERVICENOW_SECRET_NAMESPACE", "argocd-ephemeral-access")
	secretName := p.getEnvVarWithDefault("SERVICENOW_SECRET_NAME", "servicenow-secret")

	return p.getCredentialsFromSecret(namespace, secretName, "username", "password")
}

func (p *ServiceNowPlugin) doGetRequest(requestURI string) *http.Response {
	apiCall := fmt.Sprintf("%s%s", serviceNowUrl, requestURI)
	p.Logger.Debug("apiCall: " + apiCall)

	req, err := http.NewRequest("GET", apiCall, nil)
	if err != nil {
		errorText := "Error in NewRequest: " + err.Error()
		p.Logger.Error(errorText)
		panic(errorText)
	}

	req.Header.Add("Accept", "application/json")
	req.SetBasicAuth(serviceNowUsername, serviceNowPassword)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		errorText := "Error in client.Do: " + err.Error()
		p.Logger.Error(errorText)
		panic(errorText)
	}

	return resp
}

func (p *ServiceNowPlugin) checkAPIResult(resp *http.Response, body []byte) []byte {

	if (resp.StatusCode >= 500 && resp.StatusCode <= 599) || strings.Contains(string(body), "<html>") {
		errorText := "ServiceNow API server is down"
		p.Logger.Error(errorText)
		panic(errorText)
	}

	if resp.StatusCode >= 400 && resp.StatusCode <= 499 {
		errorText := "ServiceNow API changed"
		p.Logger.Error(errorText)
		panic(errorText)
	}

	return body
}

func (p *ServiceNowPlugin) getFromServiceNowAPI(requestURI string) []byte {

	resp := p.doGetRequest(requestURI)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		errorText := "Error in io.ReadAll: " + err.Error()
		p.Logger.Error(errorText)
		panic(errorText)
	}

	p.Logger.Debug(string(body))
	return p.checkAPIResult(resp, body)
}

func (p *ServiceNowPlugin) patchServiceNowAPI(requestURI string, data string) []byte {

	apiCall := fmt.Sprintf("%s%s", serviceNowUrl, requestURI)
	p.Logger.Debug("apiCall: " + apiCall)
	p.Logger.Debug("Data: " + string(data))

	req, err := http.NewRequest("PATCH", apiCall, strings.NewReader(data))
	if err != nil {
		errorText := "Error in NewRequest: " + err.Error()
		p.Logger.Error(errorText)
		panic(errorText)
	}

	req.Header.Add("Accept", "application/json")
	req.SetBasicAuth(serviceNowUsername, serviceNowPassword)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		errorText := "Error in client.Do: " + err.Error()
		p.Logger.Error(errorText)
		panic(errorText)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		errorText := "Error in io.ReadAll: " + err.Error()
		p.Logger.Error(errorText)
		panic(errorText)
	}

	p.Logger.Debug(string(body))
	return p.checkAPIResult(resp, body)
}

func (p *ServiceNowPlugin) getGlobalVars() {
	serviceNowUrl = p.getEnvVarWithPanic("SERVICE_NOW_URL", "No Service Now URL given (environment variable SERVICE_NOW_URL is empty)")
	timezone = p.getEnvVarWithDefault("TIMEZONE", "UTC")
	ciLabel = p.getEnvVarWithDefault("CI_LABEL", "ci-name")
	p.getK8sConfig()

	serviceNowUsername, serviceNowPassword = p.getServiceNowCredentials()
}

func (p *ServiceNowPlugin) getCI(ciName string) *cmdb_servicenow_type {

	requestURI := fmt.Sprintf("/api/now/table/cmdb_ci?name=%s&sysparm_fields=install_status,name", ciName)
	response := p.getFromServiceNowAPI(requestURI)

	var cmdbResults cmdb_results_service_now_type
	err := json.Unmarshal(response, &cmdbResults)
	if err != nil {
		errorText := fmt.Sprintf("Error in json.Unmarshal: %s (%s)", err.Error(), response)
		p.Logger.Error(errorText)
		panic(errorText)
	}

	if len(cmdbResults.Result) == 0 {
		errorText := fmt.Sprintf("No CI with name %s found", ciName)
		p.Logger.Error(errorText)
		panic(errorText)
	}

	p.Logger.Debug("InstallStatus: " + cmdbResults.Result[0].InstallStatus + ", CI name: " + cmdbResults.Result[0].Name)

	return cmdbResults.Result[0]
}

func (p *ServiceNowPlugin) getChanges(ciName string, sysparm_offset int) ([]*change_servicenow_type, int) {

	requestURI := fmt.Sprintf("/api/now/table/change_request?cmdb_ci=%s&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date,sys_id&sysparm_limit=%d&sysparm_offset=%d", ciName, sysparm_limit, sysparm_offset)
	response := p.getFromServiceNowAPI(requestURI)

	var changeResults change_results_servicenow_type
	err := json.Unmarshal(response, &changeResults)
	if err != nil {
		errorText := fmt.Sprintf("Error in json.Unmarshal: %s (%s)", err.Error(), response)
		p.Logger.Error(errorText)
		panic(errorText)
	}

	if len(changeResults.Result) == 0 {
		errorText := "No changes found"
		p.Logger.Error(errorText)
		panic(errorText)
	}

	return changeResults.Result, sysparm_offset + len(changeResults.Result)
}

func (p *ServiceNowPlugin) parseChange(changeServiceNow change_servicenow_type) change_type {
	var change change_type

	p.Logger.Debug(fmt.Sprintf("Change: Type: %s, Number: %s, Short description: %s, Start Date: %s, End Date: %s, SysId: %s",
		changeServiceNow.Type,
		changeServiceNow.Number,
		changeServiceNow.ShortDescription,
		changeServiceNow.StartDate,
		changeServiceNow.EndDate,
		changeServiceNow.SysId))

	change.Type = changeServiceNow.Type
	change.Number = changeServiceNow.Number
	change.ShortDescription = changeServiceNow.ShortDescription
	change.StartDate = p.convertTime(changeServiceNow.StartDate)
	change.EndDate = p.convertTime(changeServiceNow.EndDate)
	change.SysId = changeServiceNow.SysId

	return change
}

func (p *ServiceNowPlugin) checkCI(CI cmdb_servicenow_type) string {
	errorText := ""
	installStatus := CI.InstallStatus
	ciName := CI.Name

	validInstallStatus := []string{
		"1", // Installed
		"3", // In maintenance
		"4", // Pending install
		"5", // Pending repair
	}

	if !slices.Contains(validInstallStatus, installStatus) {
		errorText = fmt.Sprintf("Invalid install status (%s) for CI %s", installStatus, ciName)
	}

	return errorText
}

func (p *ServiceNowPlugin) checkChange(change change_type) (string, time.Duration) {
	errorText := ""
	var remainingTime time.Duration
	remainingTime = 0

	currentTime := time.Now()

	if change.EndDate.Before(currentTime) ||
		change.StartDate.After(currentTime) {
		errorText = fmt.Sprintf("Change %s (%s) is not in the valid time range. start date: %s and end date: %s (current date: %s)",
			change.Number,
			change.ShortDescription,
			p.getLocalTime(change.StartDate),
			p.getLocalTime(change.EndDate),
			p.getLocalTime(currentTime))
		p.Logger.Debug(errorText)
	} else {
		remainingTime = change.EndDate.Sub(time.Now())
	}

	return errorText, remainingTime
}

func (p *ServiceNowPlugin) processCI(ciName string) string {
	CI := p.getCI(ciName)
	errorString := p.checkCI(*CI)

	return errorString
}

func (p *ServiceNowPlugin) processChanges(ciName string) (string, time.Duration, *change_type) {
	var sysparm_offset = 0

	serviceNowChanges, sysparm_offset := p.getChanges(ciName, sysparm_offset)
	var validChange *change_type = nil
	var changeRemainingTime time.Duration = 0
	var remainingTime time.Duration = 0

	errorString := ""
	for {
		for _, serviceNowChange := range serviceNowChanges {
			change := p.parseChange(*serviceNowChange)
			errorString, remainingTime = p.checkChange(change)
			if errorString == "" {
				validChange = &change
				changeRemainingTime = remainingTime
				break
			}
		}
		if validChange != nil || len(serviceNowChanges) < sysparm_limit {
			break
		} else {
			serviceNowChanges, sysparm_offset = p.getChanges(ciName, sysparm_offset)
		}
	}

	return errorString, changeRemainingTime, validChange
}

func (p *ServiceNowPlugin) postNote(sysId string, noteText string) {
	requestURI := fmt.Sprintf("/api/now/table/change_request/%s", sysId)

	p.patchServiceNowAPI(requestURI, noteText)
}

// Public methods

func (p *ServiceNowPlugin) Init() error {
	p.Logger.Debug("This is a call to the Init method")
	// p.getGlobalVars cannot be put in the Init method: the variables will be lost between different calls

	return nil
}

func (p *ServiceNowPlugin) GrantAccess(ar *api.AccessRequest, app *argocd.Application) (*plugin.GrantResponse, error) {
	p.Logger.Debug("This is a call to the GrantAccess method")
	p.showRequest(ar, app)

	requesterName := ar.Spec.Subject.Username
	requestedRole := ar.Spec.Role.TemplateRef.Name
	namespace := ar.Spec.Application.Namespace
	arName := ar.ObjectMeta.Name
	arDuration := ar.Spec.Duration.Duration
	applicationName := ar.Spec.Application.Name

	p.getGlobalVars()

	ciName := p.getCIName(app)
	if ciName == "\"\"" {
		errorText := fmt.Sprintf("No CI name found: expected label with name %s in application %s", ciLabel, applicationName)
		p.Logger.Error(errorText)
		return p.deny(errorText)
	}

	errorString := p.processCI(ciName)
	if errorString != "" {
		p.Logger.Error("Access Denied for " + requesterName + " : " + errorString)
		return p.deny(errorString)
	}

	errorString, changeRemainingTime, validChange := p.processChanges(ciName)

	if errorString == "" {
		duration, endDateTime := p.determineDurationAndRealEndTime(arDuration, changeRemainingTime, validChange.EndDate)
		ar.Spec.Duration.Duration = duration

		// AbortJob is only needed when the end date of the change is more than the default for the access request time in
		// the future, otherwise the ArgoCD Ephemeral Access Extension will revoke the permissions
		if arDuration > changeRemainingTime {
			p.createRevokeJob(namespace, arName, validChange.EndDate)
		}

		jsonAr, _ := json.Marshal(ar)
		p.Logger.Debug(string(jsonAr))

		grantedAccessText, grantedUIText, grantedAccessServiceNowText := p.determineGrantedTexts(requesterName, requestedRole, *validChange, duration, endDateTime)
		p.Logger.Info(grantedAccessText)
		p.Logger.Debug(grantedUIText)

		note := fmt.Sprintf("{\"work_notes\":\"%s\"}", grantedAccessServiceNowText)
		p.postNote(validChange.SysId, note)
		return p.grant(grantedUIText)
	} else {
		p.Logger.Error(fmt.Sprintf("Access Denied for %s, role %s: %s", requesterName, requestedRole, errorString))
		return p.deny(errorString)
	}
}

func (p *ServiceNowPlugin) RevokeAccess(ar *api.AccessRequest, app *argocd.Application) (*plugin.RevokeResponse, error) {
	return nil, nil
}

func main() {
	logger, err := log.NewPluginLogger()
	if err != nil {
		panic(fmt.Sprintf("Error creating plugin logger: %s", err))
	}

	p := &ServiceNowPlugin{
		Logger: logger,
	}

	srvConfig := plugin.NewServerConfig(p, logger)

	goPlugin.Serve(srvConfig)
}
