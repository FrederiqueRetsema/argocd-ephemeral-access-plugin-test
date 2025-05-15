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

type cmdb_snow_type *struct {
	InstallStatus string `json:"install_status"`
	Name          string `json:"name"`
}

type cmdb_results_snow_type struct {
	Result []cmdb_snow_type `json:"result"`
}

type change_snow_type *struct {
	Type             string  `json:"type"`
	Number           string  `json:"number"`
	State            float64 `json:"state"`
	Phase            string  `json:"phase"`
	CMDBCi           string  `json:"cmdb_ci"`
	Active           string  `json:"active"`
	EndDate          string  `json:"end_date"`
	ShortDescription string  `json:"short_description"`
	StartDate        string  `json:"start_date"`
	Approval         string  `json:"approval"`
}

type change_type struct {
	Type             string
	Number           string
	State            float64
	Phase            string
	CMDBCi           string
	Active           string
	EndDate          time.Time
	ShortDescription string
	StartDate        time.Time
	Approval         string
}

type change_results_snow_type struct {
	Result []change_snow_type `json:"result"`
}

const sysparm_limit = 5

var snowUrl string
var timezone string
var k8sconfig *rest.Config
var k8sclientset kubernetes.Interface

func (p *ServiceNowPlugin) Init() error {
	p.Logger.Debug("This is a call to the Init method")
	return nil
}

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

func (p *ServiceNowPlugin) getK8sConfig() {
	var err error
	k8sconfig, err = rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}

	k8sclientset, err = kubernetes.NewForConfig(k8sconfig)
	if err != nil {
		panic(err.Error())
	}
}

func (p *ServiceNowPlugin) getCIName(app *argocd.Application, ciLabel string) string {
	ciName := string(app.ObjectMeta.Labels[ciLabel])
	p.Logger.Debug(fmt.Sprintf("ciLabel %s found: %s", ciLabel, ciName))

	return ciName
}

func (p *ServiceNowPlugin) showRequest(ar *api.AccessRequest, app *argocd.Application) {
	username := ar.Spec.Subject.Username
	role := ar.Spec.Role.TemplateRef.Name
	namespace := ar.Spec.Application.Namespace
	application := ar.Spec.Application.Name
	duration := ar.Spec.Duration.Duration.String()

	infoText := fmt.Sprintf("Call to GrantAccess: username: %s, role: %s, application: [%s]%s, duration: %s", username, role, namespace, application, duration)
	p.Logger.Info(infoText)

	jsonAr, _ := json.Marshal(ar)
	jsonApp, _ := json.Marshal(app)
	p.Logger.Debug("jsonAr: " + string(jsonAr))
	p.Logger.Debug("jsonApp: " + string(jsonApp))
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

func (p *ServiceNowPlugin) getSNOWCredentials() (string, string) {
	namespace := p.getEnvVarWithDefault("SECRET_NAMESPACE", "argocd-ephemeral-access")
	secretName := p.getEnvVarWithDefault("SNOW_SECRET_NAME", "snow-secret")

	return p.getCredentialsFromSecret(namespace, secretName, "username", "password")
}

func (p *ServiceNowPlugin) getFromSNOWAPI(username string, password string, apiCall string) []byte {
	p.Logger.Debug("apiCall: " + apiCall)

	req, err := http.NewRequest("GET", apiCall, nil)
	if err != nil {
		errorText := "Error in NewRequest: " + err.Error()
		p.Logger.Error(errorText)
		panic(errorText)
	}

	req.Header.Add("Accept", "application/json")
	req.SetBasicAuth(username, password)

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
	if strings.Contains(string(body), "<html>") {
		errorText := "Service Now API server is down"
		p.Logger.Error(errorText)
		panic(errorText)
	}

	return body
}

func (p *ServiceNowPlugin) getCI(username string, password string, ciName string) cmdb_snow_type {

	apiCall := fmt.Sprintf("%s/api/now/table/cmdb_ci?name=%s&sysparm_fields=install_status,name", snowUrl, ciName)
	response := p.getFromSNOWAPI(username, password, apiCall)

	var cmdbResults cmdb_results_snow_type
	err := json.Unmarshal(response, &cmdbResults)
	if err != nil {
		errorText := "Error in json.Unmarshal: " + err.Error()
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

func (p *ServiceNowPlugin) getChanges(username string, password string, ciName string, sysparm_offset int) ([]change_snow_type, int) {

	apiCall := fmt.Sprintf("%s/api/now/table/change_request?cmdb_ci=%s&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date&sysparm_limit=%d&sysparm_offset=%d", snowUrl, ciName, sysparm_limit, sysparm_offset)
	response := p.getFromSNOWAPI(username, password, apiCall)

	var changeResults change_results_snow_type
	err := json.Unmarshal(response, &changeResults)
	if err != nil {
		errorText := "Error in json.Unmarshal: " + err.Error()
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

func (p *ServiceNowPlugin) parseChange(changeSnow change_snow_type) change_type {
	var change change_type

	p.Logger.Debug(fmt.Sprintf("Change: Type: %s, Short description: %s, Start Date: %s, End Date: %s",
		changeSnow.Type,
		changeSnow.ShortDescription,
		changeSnow.StartDate,
		changeSnow.EndDate))

	change.Type = changeSnow.Type
	change.Number = changeSnow.Number
	change.State = changeSnow.State
	change.CMDBCi = changeSnow.CMDBCi
	change.Active = changeSnow.Active
	change.Approval = changeSnow.Approval
	change.ShortDescription = changeSnow.ShortDescription
	change.StartDate = p.convertTime(changeSnow.StartDate)
	change.EndDate = p.convertTime(changeSnow.EndDate)

	return change
}

func (p *ServiceNowPlugin) checkCI(CI cmdb_snow_type) string {
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

func (p *ServiceNowPlugin) DenyAccess(reason string) (*plugin.GrantResponse, error) {
	return &plugin.GrantResponse{
		Status:  plugin.GrantStatusDenied,
		Message: reason,
	}, nil
}

func (p *ServiceNowPlugin) getLocalTime(t time.Time) string {
	loc, _ := time.LoadLocation(timezone)

	return fmt.Sprintf("%02d:%02d:%02d",
		t.In(loc).Hour(),
		t.In(loc).Minute(),
		t.In(loc).Second())
}

// https://dev.to/narasimha1997/create-kubernetes-jobs-in-golang-using-k8s-client-go-api-59ej
func (p *ServiceNowPlugin) createAbortJob(namespace string, accessrequestName string, jobStartTime time.Time) {
	p.Logger.Debug(fmt.Sprintf("createAbortJob: %s, %s", namespace, accessrequestName))
	jobName := strings.Replace("stop-"+accessrequestName, ".", "-", -1)
	cmd := fmt.Sprintf("curl --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt --header \"Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" -X DELETE https://kubernetes.default.svc.cluster.local/apis/ephemeral-access.argoproj-labs.io/v1alpha1/namespaces/argocd/accessrequests/%s", accessrequestName)
	cronjobs := k8sclientset.BatchV1().CronJobs(namespace)
	var backOffLimit int32 = 0

	// jobSpec := &batchv1.Job{
	//     ObjectMeta: metav1.ObjectMeta{
	//         Name:      jobName,
	//         Namespace: namespace,
	//     },
	//     Spec: batchv1.JobSpec{
	//         Template: v1.PodTemplateSpec{
	//             Spec: v1.PodSpec{
	// 				ServiceAccountName: "remove-accessrequest-job-sa",
	//                 Containers: []v1.Container{
	//                     {
	//                         Name:    jobName,
	//                         Image:   "curlimages/curl:latest",
	//                         Command: strings.Split(cmd, " "),
	//                     },
	//                 },
	//                 RestartPolicy: v1.RestartPolicyNever,
	//             },
	//         },
	//         BackoffLimit: &backOffLimit,
	//     },
	// }
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
									Image:   "curlimages/curl:latest",
									Command: strings.Split(cmd, " "),
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

func (p *ServiceNowPlugin) GrantAccess(ar *api.AccessRequest, app *argocd.Application) (*plugin.GrantResponse, error) {
	p.Logger.Debug("This is a call to the GrantAccess method")
	p.showRequest(ar, app)

	requesterName := ar.Spec.Subject.Username
	requestedRole := ar.Spec.Role.TemplateRef.Name
	namespace := ar.Spec.Application.Namespace
	arName := ar.ObjectMeta.Name
	arDuration := ar.Spec.Duration.Duration

	sysparm_offset := 0

	snowUrl = p.getEnvVarWithPanic("SERVICE_NOW_URL", "No Service Now URL given (environment variable SERVICE_NOW_URL is empty)")
	if snowUrl == "" {
		return p.DenyAccess("No environment variable SERVICE_NOW_URL found, cannot find SNOW API")
	}

	timezone = p.getEnvVarWithDefault("TIMEZONE", "UTC")
	p.getK8sConfig()

	username, password := p.getSNOWCredentials()

	ciLabel := p.getEnvVarWithDefault("CI_LABEL", "ci_name")
	ciName := p.getCIName(app, ciLabel)
	if ciName == "\"\"" {
		application := ar.Spec.Application.Name
		return p.DenyAccess("No label " + ciLabel + " in app " + application)
	}
	p.Logger.Debug("Search for " + ciName + " in the CMDB...")

	CI := p.getCI(username, password, ciName)
	errorString := p.checkCI(CI)
	if errorString != "" {
		p.Logger.Error("Access Denied for " + requesterName + " : " + errorString)
		return p.DenyAccess(errorString)
	}

	snowChanges, sysparm_offset := p.getChanges(username, password, ciName, sysparm_offset)
	var validChange *change_type = nil
	var changeRemainingTime time.Duration = 0
	var remainingTime time.Duration = 0
	errorString = ""
	for {
		for _, snowChange := range snowChanges {
			change := p.parseChange(snowChange)
			errorString, remainingTime = p.checkChange(change)
			if errorString == "" {
				validChange = &change
				changeRemainingTime = remainingTime
				break
			}
		}
		if validChange != nil || len(snowChanges) < sysparm_limit {
			break
		} else {
			snowChanges, sysparm_offset = p.getChanges(username, password, ciName, sysparm_offset)
		}
	}

	if validChange != nil {
		grantedAccessText := fmt.Sprintf("Granted access for %s: %s change %s (%s), role %s, from %s to %s",
			requesterName,
			validChange.Type,
			validChange.Number,
			validChange.ShortDescription,
			requestedRole,
			p.getLocalTime(time.Now()),
			p.getLocalTime(validChange.EndDate))
		p.Logger.Info(grantedAccessText)
	} else {
		p.Logger.Error(fmt.Sprintf("Access Denied for %s, role %s: %s", requesterName, requestedRole, errorString))
		return p.DenyAccess(errorString)
	}

	// Set duration to the time left for this (valid) change, unless original request was
	// shorter (otherwise the ephemeral access extension itself will abort the accessrequest)
	var endLocalDateString string

	if arDuration > changeRemainingTime {
		ar.Spec.Duration.Duration = changeRemainingTime
		endLocalDateString = p.getLocalTime(validChange.EndDate)
		p.createAbortJob(namespace, arName, validChange.EndDate)
	} else {
		changeRemainingTime = arDuration

		var endDateTime time.Time = time.Now().Add(changeRemainingTime)
		endLocalDateString = p.getLocalTime(endDateTime)
	}

	jsonAr, _ := json.Marshal(ar)
	p.Logger.Debug(string(jsonAr))

	grantedAccessTextUI := fmt.Sprintf("Granted access: change __%s__ (%s), until __%s (%s)__",
		validChange.Number,
		validChange.ShortDescription,
		endLocalDateString,
		changeRemainingTime.Truncate(time.Second).String())

	p.Logger.Debug(grantedAccessTextUI)
	return &plugin.GrantResponse{
		Status:  plugin.GrantStatusGranted,
		Message: grantedAccessTextUI,
	}, nil
}

// RevokeAccess is the method that will be called by the EphemeralAccess controller
// when an AccessRequest is expired. Plugins authors may decide to not implement this
// method depending on the use case. In this case it is safe to just return nil, nil.
func (p *ServiceNowPlugin) RevokeAccess(ar *api.AccessRequest, app *argocd.Application) (*plugin.RevokeResponse, error) {
	p.Logger.Info("This is a call to the RevokeAccess method")
	return &plugin.RevokeResponse{
		Status: plugin.RevokeStatusRevoked,
		// The message can be returned as markdown
		Message: "Revoked access by the ServiceNow plugin",
	}, nil
}

// main must be defined as it is the plugin entrypoint. It will be automatically called
// by the EphemeralAccess controller.
func main() {
	// NewPluginLogger will return a logger that will respect the same level and format
	// defined to the EphemeralAccess controller.
	logger, err := log.NewPluginLogger()
	if err != nil {
		panic(fmt.Sprintf("Error creating plugin logger: %s", err))
	}

	// create a new instance of your plugin after initializing the logger and other
	// dependencies. However it is preferable to leave the main function lean and
	// initialize plugin dependencies in the `Init` method.
	p := &ServiceNowPlugin{
		Logger: logger,
	}

	// create the plugin server config
	srvConfig := plugin.NewServerConfig(p, logger)
	// initialize the plugin server
	goPlugin.Serve(srvConfig)
}
