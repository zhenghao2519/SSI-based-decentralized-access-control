package app.rbac

import future.keywords.contains
import future.keywords.if
import future.keywords.in
import data.test.rbacdata

default allow := false


# Allow the action if the user has the role which is granted permission to perform the action.
allow if {
	some role_name in requested_roles
    input.role == role_name
}

# List all roles with a proper grants for requested service
requested_roles contains role.name if {
    some role in rbacdata.role_grants
    some grant in role.grants
    grant.action == input.action
    grant.object == input.object
}

requested_attrs := ["role"]
requested_preds := []