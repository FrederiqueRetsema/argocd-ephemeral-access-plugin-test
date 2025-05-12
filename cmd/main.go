package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
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

type cmdb_type *struct {
	InstallStatus string `json:"install_status"`
	Name string `json:"name"`
}

type cmdb_results_type *struct {
	Result []cmdb_type `json:"result"` 
}

func (p *ServiceNowPlugin) Init() error {
	p.Logger.Debug("This is a call to the Init method")
	return nil
}

func (p *ServiceNowPlugin) showRequest(ar *api.AccessRequest, app *argocd.Application) {
	username := ar.Spec.Subject.Username
	role := ar.Spec.Role.TemplateRef.Name
	namespace := ar.Spec.Application.Namespace
	application := ar.Spec.Application.Name
	duration := ar.Spec.Duration.Duration.String()

	infoText := fmt.Sprintf("GrantAccess: username: %s, role: %s, application: [%s]%s, duration: %s", username, role, namespace, application, duration)
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
	namespace := os.Getenv("EPHEMERAL_ACCESS_NAMESPACE")
	if namespace == "" {
		p.Logger.Debug("No EPHEMERAL_ACCESS_NAMESPACE environment variable, assuming argocd-ephemeral-access")
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

	jsonSecret, _ := json.Marshal(secret)
	p.Logger.Debug(string(jsonSecret))

	return string(secret.Data["username"]), string(secret.Data["password"])
}

func (p *ServiceNowPlugin) getCI(username string, password string, ciName string) *cmdb_type {
	snowUrl := os.Getenv("SERVICE_NOW_URL")
	if snowUrl == "" {
		panic(errors.New("No Service Now URL given (environment variable SERVICE_NOW_URL is empty)"))
	}

	url := fmt.Sprintf("%s/api/now/table/cmdb_ci?name=%s&sysparm_fields=install_status,name", snowUrl, ciName)
	p.Logger.Debug("Call to: " + url)

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
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

	var cmdbResults cmdb_results_type
	err = json.Unmarshal(body, &cmdbResults)
	if err != nil {
		p.Logger.Error("Error in json.Unmarshal: " + err.Error())
	}

	p.Logger.Debug("InstallStatus: "+cmdbResults.Result[0].InstallStatus+", CI name: "+cmdbResults.Result[0].Name)

	return cmdbResults.Result[0]
}

func (p *ServiceNowPlugin) checkCI(CI cmdb_type) (*plugin.GrantResponse, error) {



func (p *ServiceNowPlugin) DenyAccess(reason string) (*plugin.GrantResponse, error) {
	return &plugin.GrantResponse{
		Status:  plugin.GrantStatusDenied,
		Message: reason,
	}, nil
}

func (p *ServiceNowPlugin) GrantAccess(ar *api.AccessRequest, app *argocd.Application) (*plugin.GrantResponse, error) {
	p.Logger.Debug("This is a call to the GrantAccess method")

	username, password := p.getSNOWCredentials()

	p.showRequest(ar, app)

	ciLabel, ciName := p.getCIName(app)
	if ciName == "\"\"" {
		application := ar.Spec.Application.Name
		return p.DenyAccess("No label " + ciLabel + " in app " + application)
	}
	p.Logger.Debug("Search for " + ciName + " in the CMDB...")

	// curl "https://dev202720.service-now.com/api/sn_chg_rest/change?cmdb_ci=f68cb36b83556210674cf655eeaad360" --request GET --header "Accept:application/json" --user 'admin':'AYMAo^h8+0tq'

	_ = p.getCI(username, password, ciName)

	// Set duration to 5 minutes
	ar.Spec.Duration.Duration = 5 * time.Minute
	jsonAr, _ := json.Marshal(ar)
	p.Logger.Debug(string(jsonAr))

	return &plugin.GrantResponse{
		Status: plugin.GrantStatusGranted,
		// The message can be returned as markdown
		Message: "Granted access by the Topdesk plugin",
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
		Message: "Revoked access by the Topdesk plugin",
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
