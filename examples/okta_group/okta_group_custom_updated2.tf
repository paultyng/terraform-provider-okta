resource "okta_group" "test" {
  name        = "testAcc"
  description = "testing, testing"
  custom_profile_attributes = jsonencode({
    "testSchema1" = "moretesting1234",
    "testSchema2" = false,
    "testSchema3" = 12345
  })
}

// Test Schema
resource "okta_group_schema_property" "test1" {
  index       = "testSchema1"
  title       = "TestSchema1"
  type        = "string"
  description = "Test string schema"
  master      = "OKTA"
}

resource "okta_group_schema_property" "test2" {
  index       = "testSchema2"
  title       = "TestSchema2"
  type        = "bool"
  description = "Test bool schema"
  master      = "OKTA"
}

resource "okta_group_schema_property" "test3" {
  index       = "testSchema3"
  title       = "TestSchema3"
  type        = "number"
  description = "Test bool schema"
  master      = "OKTA"
}
