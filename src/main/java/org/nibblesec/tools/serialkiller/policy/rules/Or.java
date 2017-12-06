package org.nibblesec.tools.serialkiller.policy.rules;

import java.util.Arrays;

/**
 * An OR-expression for a deserialization ruleset.
 * 
 * @author Wolfgang Ettlinger
 *
 */
public class Or implements DeserializationPolicyRule {
	private DeserializationPolicyRule[] rules;
	
	public Or(DeserializationPolicyRule... rules) {
		this.rules = rules;
	}
	
	@Override
	public boolean matches(Class<?> clz) {
		for(DeserializationPolicyRule rule : rules){
			if(rule.matches(clz)){
				return true;
			}
		}
		
		return false;
	}
	
	@Override
	public String describe() {
		return String.join(" OR ", (String[]) Arrays.stream(rules).map(r -> "( "+ r.describe() + ")").toArray());
	}
}
