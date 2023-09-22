package okta

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/okta/terraform-provider-okta/sdk"
)

func TestAccResourceOktaAppOAuthApplication_apiScope(t *testing.T) {
	mgr := newFixtureManager("resources", appOAuthAPIScope, t.Name())
	plainConfig := mgr.GetFixtures("basic.tf", t)
	plainUpdatedConfig := mgr.GetFixtures("basic_updated.tf", t)
	resourceName := fmt.Sprintf("%s.test_app_scopes", appOAuthAPIScope)

	// Replace example org url with actual url to prevent API error
	config := strings.ReplaceAll(plainConfig, "https://your.okta.org", getOktaDomainName())
	updatedConfig := strings.ReplaceAll(plainUpdatedConfig, "https://your.okta.org", getOktaDomainName())

	oktaResourceTest(t, resource.TestCase{
		PreCheck:          testAccPreCheck(t),
		ErrorCheck:        testAccErrorChecks(t),
		ProviderFactories: testAccProvidersFactories,
		CheckDestroy:      checkResourceDestroy(appOAuth, createDoesAppExist(sdk.NewOpenIdConnectApplication())),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					ensureResourceExists(resourceName, apiScopeExists),
					resource.TestCheckResourceAttrSet(resourceName, "app_id"),
					resource.TestCheckResourceAttrSet(resourceName, "issuer"),
					resource.TestCheckTypeSetElemAttr(resourceName, "scopes.*", "okta.users.read"),
				),
			},
			{
				Config: updatedConfig,
				Check: resource.ComposeTestCheckFunc(
					ensureResourceExists(resourceName, apiScopeExists),
					resource.TestCheckResourceAttrSet(resourceName, "app_id"),
					resource.TestCheckResourceAttrSet(resourceName, "issuer"),
					resource.TestCheckTypeSetElemAttr(resourceName, "scopes.*", "okta.users.read"),
					resource.TestCheckTypeSetElemAttr(resourceName, "scopes.*", "okta.users.manage"),
				),
			},
		},
	})
}

func apiScopeExists(id string) (bool, error) {
	client := sdkV2ClientForTest()
	scopes, _, err := client.Application.ListScopeConsentGrants(context.Background(), id, nil)
	if err != nil {
		return false, fmt.Errorf("failed to get application scope consent grants: %v", err)
	}
	if len(scopes) > 0 {
		return true, nil
	}
	return false, nil
}

func getOktaDomainName() string {
	domain := os.Getenv("OKTA_BASE_URL")
	if domain == "" {
		domain = "okta.com"
	}
	return fmt.Sprintf("https://%v.%v", os.Getenv("OKTA_ORG_NAME"), domain)
}
