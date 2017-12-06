package org.nibblesec.tools.serialkiller.policy.rules;

/**
 * An Interface for rule int the blacklist or whitelist.
 * 
 * @author Wolfgang Ettlinger
 *
 */
public interface DeserializationPolicyRule {
	boolean matches(Class<?> clz);
	String describe();
}
