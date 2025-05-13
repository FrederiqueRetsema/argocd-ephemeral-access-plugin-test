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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ServiceNowPlugin struct {
	Logger hclog.Logger
}

type cmdb_snow_type *struct {
	InstallStatus string `json:"install_status"`
	Name string `json:"name"`
}

type cmdb_results_snow_type *struct {
	Result []cmdb_snow_type `json:"result"` 
}

type change_snow_type struct {
	Type string `json:"type"`
	Number string `json:"number"`
	State float64 `json:"state"`
	Phase string `json:"phase"`
	CMDBCi string `json:"cmdb_ci"`
	Active string `json:"active"`
	EndDate string `json:"end_date"`
	ShortDescription string `json:"short_description"`
	StartDate string `json:"start_date"`
	Approval string `json:"approval"` 
}

type change_type *struct {
	Type string 
	Number string 
	State float64 
	Phase string 
	CMDBCi string 
	Active string 
	EndDate time.Time 
	ShortDescription string 
	StartDate time.Time 
	Approval string  
}

type change_results_snow_type *struct {
	Result []*change_snow_type `json:"result"`
}

func (p *ServiceNowPlugin) Init() error {
	p.Logger.Debug("This is a call to the Init method")
	return nil
}

const sysparm_limit = 5
var snowUrl string

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

func (p *ServiceNowPlugin) getCIName(app *argocd.Application) (string, string) {
	ciLabel := os.Getenv("CI_LABEL")
	if ciLabel == "" {
		p.Logger.Debug("No CI_LABEL environment variable, assuming ci_name")
		ciLabel = "ci_name"
	}

	p.Logger.Debug("Look for " + ciLabel + " in metadata...")
	ciName := app.ObjectMeta.Labels[ciLabel]
	p.Logger.Debug("ciLabel found = " + ciName)

	return ciLabel, string(ciName)
}

func (p *ServiceNowPlugin) getSNOWCredentials() (string, string) {
	namespace := os.Getenv("SECRET_NAMESPACE")
	if namespace == "" {
		p.Logger.Debug("No SECRET_NAMESPACE environment variable, assuming argocd-ephemeral-access")
		namespace = "argocd-ephemeral-access"
	}

	secretName := os.Getenv("SNOW_SECRET_NAME")
	if secretName == "" {
		p.Logger.Debug("No SNOW_SECRET_NAME environment variable, assuming snow-secret")
		secretName = "snow-secret"
	}

	p.Logger.Debug("Get credentials from secret " + secretName + "...")

	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	secret, err := clientset.CoreV1().Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
	if err != nil {
		panic(err.Error())
	}

	return string(secret.Data["username"]), string(secret.Data["password"])
}

func (p *ServiceNowPlugin) getFromSNOWAPI(username string, password string, apiCall string) []byte {
	if snowUrl == "" {
		panic(errors.New("No Service Now URL given (environment variable SERVICE_NOW_URL is empty)"))
	}

	p.Logger.Debug("apiCall: " + apiCall)

	client := &http.Client{}
	req, err := http.NewRequest("GET", apiCall, nil)
	if err != nil {
		p.Logger.Error("Error in NewRequest: " + err.Error())
	}

	req.Header.Add("Accept", "application/json")
	req.SetBasicAuth(username, password)
	resp, err := client.Do(req)
	if err != nil {
		p.Logger.Error("Error in client.Do: " + err.Error())
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		p.Logger.Error("Error in io.ReadAll: " + err.Error())
	}

	p.Logger.Debug(string(body))

	return body
}

func (p *ServiceNowPlugin) getCI(username string, password string, ciName string) cmdb_snow_type {

	apiCall := fmt.Sprintf("%s/api/now/table/cmdb_ci?name=%s&sysparm_fields=install_status,name", snowUrl, ciName)
	response := p.getFromSNOWAPI(username, password, apiCall)

	var cmdbResults cmdb_results_snow_type
	err := json.Unmarshal(response, &cmdbResults)
	if err != nil {
		p.Logger.Error("Error in json.Unmarshal: " + err.Error())
	}

	p.Logger.Debug("InstallStatus: "+cmdbResults.Result[0].InstallStatus+", CI name: "+cmdbResults.Result[0].Name)

	return cmdbResults.Result[0]
}

func (p *ServiceNowPlugin) getChanges(username string, password string, ciName string, sysparm_offset int) ([]*change_snow_type, int) {

	apiCall := fmt.Sprintf("%s/api/now/table/change_request?cmdb_ci=%s&state=Implement&phase=Requested&approval=Approved&active=true&sysparm_fields=type,number,short_description,start_date,end_date&sysparm_limit=%d&sysparm_offset=%d", snowUrl, ciName, sysparm_limit, sysparm_offset)
	response := p.getFromSNOWAPI(username, password, apiCall)

	var changeResults change_results_snow_type
	err := json.Unmarshal(response, &changeResults)
	if err != nil {
		p.Logger.Error("Error in json.Unmarshal: " + err.Error())
	}

	return changeResults.Result, sysparm_offset+len(changeResults.Result)
}

func (p *ServiceNowPlugin) convertTime(timestring string) (time.Time) {
	goTimeString := strings.Replace(timestring," ","T",-1)+"Z"

	var goTime time.Time
	err := goTime.UnmarshalText([]byte(goTimeString))
	if err != nil {
		p.Logger.Debug("Error in converting "+timestring+" to go Time: "+err.Error())
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
	change.StartDate = p.convertTime(changeSnow.startDate)
	change.EndDate = p.convertTime(changeSnow.endDate)

	return change
}

func (p *ServiceNowPlugin) checkCI(CI cmdb_snow_type) string {
	errorText := ""
	installStatus := CI.InstallStatus
	ciName := CI.Name

	validInstallStatus := []string {
		"1",            // Installed
		"3",			// In maintenance
		"4", 			// Pending install
		"5",			// Pending repair
	}

	if !slices.Contains(validInstallStatus, installStatus) {
		errorText = fmt.Sprintf("Invalid install status (%s) for CI %s", installStatus, ciName)
	}

	return errorText
}

func (p *ServiceNowPlugin) checkChange(change *change_type) (string, time.Duration) {
	var startDateTime time.Time
	var endDateTime time.Time

	errorText := ""
	var remainingTime time.Duration
	remainingTime = 0

	currentTime := time.Now()

    if change.endDate.Before(currentTime) ||
	   change.startDate.After(currentTime) {
		errorText = fmt.Sprintf("Change %s (%s) is not in the valid time range. start date: %s and end date: %s (current date: %s)",
	                             change.Number, 
								 change.ShortDescription, 
								 p.getLocalTime(change.startDate), 
								 p.getLocalTime(change.endDate), 
								 p.getLocalTime(currentTime))
		p.Logger.Debug(errorText)
	} else {
		remainingTime = endDateTime.Sub(time.Now())
	}

	return errorText, remainingTime
}

func (p *ServiceNowPlugin) DenyAccess(reason string) (*plugin.GrantResponse, error) {
	return &plugin.GrantResponse{
		Status:  plugin.GrantStatusDenied,
		Message: reason,
	}, nil
}

func (p *ServiceNowPlugin) getLocalTime(timezone string, t time.Time) string {
	loc, _ := time.LoadLocation(timezone)

	return fmt.Sprintf("%02d:%02d:%02d", 
						t.In(loc).Hour(),
						t.In(loc).Minute(),
						t.In(loc).Second())
}

func (p *ServiceNowPlugin) GrantAccess(ar *api.AccessRequest, app *argocd.Application) (*plugin.GrantResponse, error) {
	p.Logger.Debug("This is a call to the GrantAccess method")

	changeNumber := ""
	changeType := ""
	changeShortDescription := ""
	changeEndDate := ""
	sysparm_offset := 0 
	requestedRole := ar.Spec.Role.TemplateRef.Name

	snowUrl = os.Getenv("SERVICE_NOW_URL")
	if snowUrl == "" {
		panic(errors.New("No Service Now URL given (environment variable SERVICE_NOW_URL is empty)"))
	}

	timezone := os.Getenv("TIMEZONE")
	if timezone == "" {
		p.Logger.Info("No timezone given (environment variable TIMEZONE is empty), assuming UTC")
		timezone = "UTC"
	}

	requesterName := ar.Spec.Subject.Username

	username, password := p.getSNOWCredentials()

	p.showRequest(ar, app)

	ciLabel, ciName := p.getCIName(app)
	if ciName == "\"\"" {
		application := ar.Spec.Application.Name
		return p.DenyAccess("No label " + ciLabel + " in app " + application)
	}
	p.Logger.Debug("Search for " + ciName + " in the CMDB...")

	CI := p.getCI(username, password, ciName)
	errorString := p.checkCI(CI)
	if errorString != "" {
		p.Logger.Error("Access Denied for "+requesterName+" : "+errorString)
		return p.DenyAccess(errorString)
	}

	snowChanges, sysparm_offset := p.getChanges(username, password, ciName, sysparm_offset)
	validChange := nil
	var changeRemainingTime time.Duration = 0
	var remainingTime time.Duration = 0
	errorString = ""
	for true {
		for _, snowChange := range snowChanges {
			change := p.parseChange(snowChange)
			errorString, remainingTime = p.checkChange(change)
			if errorString == "" {
				validChange = change
				break
			}
		}
		if validChange != nil || len(changes) < sysparm_limit {
			break
		} else {
			snowChanges, sysparm_offset = p.getChanges(username, password, ciName, sysparm_offset)
		}
	}
	
	if validChange != nil {		
    	grantedAccessText := fmt.Sprintf("Granted access for %s: %s change %s (%s), role %s", 
		                                 requesterName, 
										 validChange.Type, 
										 validChange.Number, 
										 validChange.ShortDescription,
										 requestedRole)
		p.Logger.Info(grantedAccessText)
	} else {
		p.Logger.Error(fmt.Sprintf("Access Denied for %s, role %s: %s", requesterName, requestedRole, errorString))
		return p.DenyAccess(errorString)
	} 
	
	// Set duration to the time left for this (valid) change, unless original request was
	// shorter (otherwise the ephemeral access extension itself will abort the accessrequest)
	var endLocalDateString string
	if ar.Spec.Duration.Duration > changeRemainingTime {  
		ar.Spec.Duration.Duration = changeRemainingTime
		endLocalDateString = p.getLocalTime(timezone, validChange.EndDate)
	} else {
		changeRemainingTime = ar.Spec.Duration.Duration

		var endDateTime time.Time = time.Now().Add(changeRemainingTime)
		endLocalDateString = p.getLocalTime(timezone, endDateTime)
	}

	jsonAr, _ := json.Marshal(ar)
	p.Logger.Debug(string(jsonAr))

	grantedAccessTextUI := fmt.Sprintf("Granted access: change __%s__ (%s), until __%s (%s)__", changeNumber, changeShortDescription, endLocalDateString, changeRemainingTime.Truncate(time.Second).String())

	p.Logger.Debug(grantedAccessTextUI)
	return &plugin.GrantResponse{
		Status: plugin.GrantStatusGranted,
		// The message can be returned as markdown
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
