# Attribute-based Access Control (ABAC)


package app.abac

import future.keywords.contains
import future.keywords.if
import future.keywords.in
import future.keywords.every
import data.test.abacdata
has_key(x, k) { x[k] }

default allow := false

allow if{
	some policy in abacdata.policies
    policy.action == input.action
    policy.object == input.object
    some rule in policy.rules
    
    # Check equility with subject attributes
    every equal_subject_attribute in rule.equal.subject{
        some value in equal_subject_attribute.value
        input[equal_subject_attribute.key] == value
    }
    
    # Check equility with object attributes
    every equal_object_attribute in rule.equal.object{
    	some value in equal_object_attribute.value
        abacdata.object_attributes[input.object][equal_object_attribute.key] == value
    }
    
    # Check equility with environment attributes
    every equal_environment_attribute in rule.equal.environment{
    	some value in equal_environment_attribute.value
        abacdata.environment_attributes[equal_environment_attribute.key] == value
    }
    
    # Check predicates with subject attributes
    every predicate_subject_attribute in rule.predicates.subject{
        input[predicate_subject_attribute.key] >= predicate_subject_attribute.higher_than
        input[predicate_subject_attribute.key] <= predicate_subject_attribute.lower_than
    }
    
    # Check predicates with object attributes
    every predicate_object_attribute in rule.predicates.object{
        abacdata.object_attributes[input.object][predicate_object_attribute.key] >= predicate_object_attribute.higher_than
        abacdata.object_attributes[input.object][predicate_object_attribute.key] <= predicate_object_attribute.lower_than
    }
    
    # Check predicates with environment attributes
    every predicate_environment_attribute in rule.predicates.environment{
        abacdata.environment_attributes[predicate_environment_attribute.key] >= predicate_environment_attribute.higher_than
        abacdata.environment_attributes[predicate_environment_attribute.key] <= predicate_environment_attribute.lower_than
    }
}

allow if{
	some policy in abacdata.policies
    policy.action == input.action
    policy.object == input.object
    some rule in policy.rules
    
    # Check equility with subject attributes
    every equal_subject_attribute in rule.equal.subject{
        some value in equal_subject_attribute.value
        input[equal_subject_attribute.key] == value
    }
    
    # Check equility with object attributes
    every equal_object_attribute in rule.equal.object{
    	some value in equal_object_attribute.value
        abacdata.object_attributes[input.object][equal_object_attribute.key] == value
    }
    
    # Check equility with environment attributes
    every equal_environment_attribute in rule.equal.environment{
    	some value in equal_environment_attribute.value
        abacdata.environment_attributes[equal_environment_attribute.key] == value
    }
    
    # Check predicates with subject attributes using Verifiable Presentation
    every predicate_subject_attribute in rule.predicates.subject{
        input[predicate_subject_attribute.optional_vp_predicates.key] == predicate_subject_attribute.optional_vp_predicates.value
    }
    
    # Check predicates with object attributes
    every predicate_object_attribute in rule.predicates.object{
        abacdata.object_attributes[input.object][predicate_object_attribute.key] >= predicate_object_attribute.higher_than
        abacdata.object_attributes[input.object][predicate_object_attribute.key] <= predicate_object_attribute.lower_than
    }
    
    # Check predicates with environment attributes
    every predicate_environment_attribute in rule.predicates.environment{
        abacdata.environment_attributes[predicate_environment_attribute.key] >= predicate_environment_attribute.higher_than
        abacdata.environment_attributes[predicate_environment_attribute.key] <= predicate_environment_attribute.lower_than
    }
}


requested_attrs contains subject_attribute.key if {
    some policy in abacdata.policies
    policy.action == input.action
    policy.object == input.object
    some rule in policy.rules
    some subject_attribute in rule.equal.subject
}

requested_preds contains subject_predicate if {
    some policy in abacdata.policies
    policy.action == input.action
    policy.object == input.object
    some rule in policy.rules
    some subject_predicate in rule.predicates.subject
}