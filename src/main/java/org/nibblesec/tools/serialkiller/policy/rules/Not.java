package org.nibblesec.tools.serialkiller.policy.rules;

import java.util.Arrays;

/**
 * A NOT-expression for a deserialization ruleset.
 * 
 * @author Wolfgang Ettlinger
 *
 */
public class Not implements DeserializationPolicyRule {
	private DeserializationPolicyRule child;
	
	public Not(DeserializationPolicyRule child) {
		this.child = child;
	}
	
	public DeserializationPolicyRule getChild() {
		return child;
	}
	
	@Override
	public boolean matches(Class<?> clz) {
		return !child.matches(clz);
	}
	
	@Override
	public String describe() {
		return String.format("NOT (%s)", child);
	}
}
