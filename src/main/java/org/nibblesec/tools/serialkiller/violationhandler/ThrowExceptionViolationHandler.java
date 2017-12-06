package org.nibblesec.tools.serialkiller.violationhandler;

import java.io.InvalidClassException;

import org.nibblesec.tools.serialkiller.ViolationType;
import org.nibblesec.tools.serialkiller.policy.rules.DeserializationPolicyRule;

/**
 * ViolationHandler that throws an exception.
 * 
 * @author Wolfgang Ettlinger
 * 
 */
public class ThrowExceptionViolationHandler implements ViolationHandler{
	@Override
	public void onViolation(Class<?> disallowedClass, ViolationType violationType, DeserializationPolicyRule rule) throws InvalidClassException {
		throw new InvalidClassException(
				disallowedClass.getName(),
				String.format("Unauthorized deserialization attempt blocked: %s (%s)%s",
						disallowedClass.getName(),
						violationType.getDescription(),
						rule != null ? "by rule: "+rule.describe() : ""));
	}
}
