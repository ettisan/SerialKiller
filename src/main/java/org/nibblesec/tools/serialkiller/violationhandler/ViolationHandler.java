package org.nibblesec.tools.serialkiller.violationhandler;

import java.io.InvalidClassException;

import org.nibblesec.tools.serialkiller.ViolationType;
import org.nibblesec.tools.serialkiller.policy.rules.DeserializationPolicyRule;

/**
 * Interface used for a class that handles deserialization policy violations.
 * 
 * @author Wolfgang Ettlinger
 *
 */
public interface ViolationHandler {
	void onViolation(Class<?> disallowedClass, ViolationType violationType, DeserializationPolicyRule rule) throws InvalidClassException;
}
