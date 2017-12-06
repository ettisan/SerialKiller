package org.nibblesec.tools.serialkiller.policy.rules;

import java.util.Arrays;

/**
 * An AND-expression for a deserialization ruleset.
 * 
 * @author Wolfgang Ettlinger
 *
 */
public class And implements DeserializationPolicyRule {
	private DeserializationPolicyRule[] rules;
	
	public And(DeserializationPolicyRule... rules) {
		this.rules = rules;
	}
	
	@Override
	public boolean matches(Class<?> clz) {
		for(DeserializationPolicyRule rule : rules){
			if(!rule.matches(clz)){
				return false;
			}
		}
		
		return true;
	}

	@Override
	public String describe() {
		return String.join(" AND ", (String[]) Arrays.stream(rules).map(r -> "( "+ r.describe() + ")").toArray());
	}
}
