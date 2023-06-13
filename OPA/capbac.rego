package app.capbac

import future.keywords.contains
import future.keywords.if
import future.keywords.in
import data.test.capbacdata

# By default, deny requests.
default allow := false

# Allow the action if the user is granted permission to perform the action.
allow if {
	# The requested access is contained in capability
	input.object == input.granted_object
    input.action == input.granted_action
    
    # The capability isasuer can be trusted for this specific capability
    some trusted_issuer in requested_issuers
    input.issuer == trusted_issuer
}

# Return a set of trusted issuers of a capability valid for accessing the requested service 
requested_issuers[requested_issuer]{
	requested_issuer = capbacdata.grants[input.object][input.action][_]
}