package okta

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
)

func dataSourceAppWsFed() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceAppWsFedRead,
		Schema: map[string]*schema.Schema{
			"label": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A display-friendly label for this app",
			},
			"site_url": {
				Type:             schema.TypeString,
				Optional:         true,
				Description:      "",
				ValidateDiagFunc: stringIsURL(validURLSchemes...),
			},
			"realm": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "",
			},
			"reply_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "",
			},
			"reply_override": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Login URL",
			},
			"name_id_format": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "",
			},
			"audience_restriction": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "",
			},
			"authn_context_class_ref": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "",
			},
			"group_filter": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "",
			},
			"group_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "",
			},
			"group_value_format": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "",
			},
			"username_attribute": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "",
			},
			"attribute_statements": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "",
			},
			"visibility": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Should the application icon be visible to users?",
			},
		},
	}
}

func dataSourceAppWsFedRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	filters, err := getAppFilters(d)
	if err != nil {
		return diag.Errorf("invalid WsFed app filters: %v", err)
	}
	var app *okta.WsFederationApplication
	if filters.ID != "" {
		respApp, _, err := getOktaClientFromMetadata(m).Application.GetApplication(ctx, filters.ID, okta.NewWsFederationApplication(), nil)
		if err != nil {
			return diag.Errorf("failed get app by ID: %v", err)
		}
		app = respApp.(*okta.WsFederationApplication)
	} else {
		re := getOktaClientFromMetadata(m).GetRequestExecutor()
		qp := &query.Params{Limit: 1, Filter: filters.Status, Q: filters.getQ()}
		req, err := re.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/apps%s", qp.String()), nil)
		if err != nil {
			return diag.Errorf("failed to list WsFed apps: %v", err)
		}
		var appList []*okta.WsFederationApplication
		_, err = re.Do(ctx, req, &appList)
		if err != nil {
			return diag.Errorf("failed to list WsFed apps: %v", err)
		}
		if len(appList) < 1 {
			return diag.Errorf("no WsFed application found with provided filter: %s", filters)
		}
		if filters.Label != "" && appList[0].Label != filters.Label {
			return diag.Errorf("no WsFed application found with the provided label: %s", filters.Label)
		}
		logger(m).Info("found multiple WsFed applications with the criteria supplied, using the first one, sorted by creation date")
		app = appList[0]
	}
	err = setAppUsersIDsAndGroupsIDs(ctx, d, getOktaClientFromMetadata(m), app.Id)
	if err != nil {
		return diag.Errorf("failed to list WsFed app groups and users: %v", err)
	}
	d.SetId(app.Id)
	_ = d.Set("label", app.Label)
	_ = d.Set("name", app.Name)
	_ = d.Set("status", app.Status)
	_ = d.Set("key_id", app.Credentials.Signing.Kid)
	// if app.Settings != nil {
	// 	// if app.Settings.SignOn != nil {
	// 	// 	err = setSamlSettings(d, app.Settings.SignOn)
	// 	// 	if err != nil {
	// 	// 		return diag.Errorf("failed to read SAML app: error setting SAML sign-on settings: %v", err)
	// 	// 	}
	// 	// }
	// 	err = setAppSettings(d, app.Settings.App)
	// 	if err != nil {
	// 		return diag.Errorf("failed to read WsFed app: failed to set WsFed app settings: %v", err)
	// 	}
	// }
	_ = d.Set("features", convertStringSliceToSetNullable(app.Features))
	_ = d.Set("user_name_template", app.Credentials.UserNameTemplate.Template)
	_ = d.Set("user_name_template_type", app.Credentials.UserNameTemplate.Type)
	_ = d.Set("user_name_template_suffix", app.Credentials.UserNameTemplate.Suffix)
	_ = d.Set("user_name_template_push_status", app.Credentials.UserNameTemplate.PushStatus)
	p, _ := json.Marshal(app.Links)
	_ = d.Set("links", string(p))
	return nil
}
