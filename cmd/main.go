package main

import (
	"fmt"

	argocd "github.com/argoproj-labs/argocd-ephemeral-access/api/argoproj/v1alpha1"
	api "github.com/argoproj-labs/argocd-ephemeral-access/api/ephemeral-access/v1alpha1"
	"github.com/hashicorp/go-hclog"

	"github.com/argoproj-labs/argocd-ephemeral-access/pkg/log"
	"github.com/argoproj-labs/argocd-ephemeral-access/pkg/plugin"
	goPlugin "github.com/hashicorp/go-plugin"
    "encoding/json"
    "time"
	"os"
)

type TopdeskPlugin struct {
	Logger hclog.Logger
}

func (p *TopdeskPlugin) Init() error {
	p.Logger.Debug("This is a call to the Init method")
	return nil
}

func (p *TopdeskPlugin) showRequest(ar *api.AccessRequest, app *argocd.Application) {
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

func (p *TopdeskPlugin) getCIName(app *argocd.Application) (string, string) {
	ciLabel := os.Getenv("CI_LABEL")
	if ciLabel == "" {
			p.Logger.Debug("No CI_LABEL environment variable, assuming ci_name")
			ciLabel = "ci_name"
	}

	p.Logger.Debug("Look for "+ciLabel+" in metadata...")
	ciName, _ := json.Marshal(app.ObjectMeta.Labels[ciLabel])

	return  ciLabel, string(ciName)
}

func (p *TopdeskPlugin) DenyAccess(reason string) (*plugin.GrantResponse, error) {
	return &plugin.GrantResponse{
		Status: plugin.GrantStatusDenied,
		Message: reason,
	}, nil
}

func (p *TopdeskPlugin) GrantAccess(ar *api.AccessRequest, app *argocd.Application) (*plugin.GrantResponse, error) {
	p.Logger.Debug("This is a call to the GrantAccess method")

	p.showRequest(ar, app)

	ciLabel, ciName := p.getCIName(app)
	if ciName == "\"\"" {
     	application := ar.Spec.Application.Name
		return p.DenyAccess("No label "+ciLabel+" in app "+application)
	}
	p.Logger.Debug("Search for "+ciName+" in the CMDB...")

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
func (p *TopdeskPlugin) RevokeAccess(ar *api.AccessRequest, app *argocd.Application) (*plugin.RevokeResponse, error) {
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
	p := &TopdeskPlugin{
		Logger: logger,
	}

	// create the plugin server config
	srvConfig := plugin.NewServerConfig(p, logger)
	// initialize the plugin server
	goPlugin.Serve(srvConfig)
}
