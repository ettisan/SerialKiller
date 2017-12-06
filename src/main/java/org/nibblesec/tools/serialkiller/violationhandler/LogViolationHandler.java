package org.nibblesec.tools.serialkiller.violationhandler;

import java.io.InvalidClassException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.nibblesec.tools.serialkiller.ViolationType;
import org.nibblesec.tools.serialkiller.policy.rules.DeserializationPolicyRule;

/**
 * ViolationHandler that logs violations using Java logging.
 * 
 * @author Wolfgang Ettlinger
 *
 */
public class LogViolationHandler implements ViolationHandler{
	private static final Logger LOGGER = Logger.getLogger(LogViolationHandler.class.getName());
	
	@Override
	public void onViolation(Class<?> disallowedClass, ViolationType violationType, DeserializationPolicyRule rule)
			throws InvalidClassException {
		LOGGER.logp(Level.SEVERE, "Deserialization of class ''{0}'' blocked, Reason: ''{1}'' Rule {2}",
				disallowedClass.getName(), violationType.getDescription(), rule.describe());
	}
}
