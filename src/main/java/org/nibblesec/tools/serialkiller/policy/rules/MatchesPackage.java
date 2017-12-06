package org.nibblesec.tools.serialkiller.policy.rules;

public class MatchesPackage implements DeserializationPolicyRule {
	private String packageName;
	
	public MatchesPackage(String packageName) {
		this.packageName = packageName;
	}
	
	@Override
	public boolean matches(Class<?> clz) {
		return clz.getPackage().getName().equals(packageName);
	}

	@Override
	public String describe() {
		return String.format("PACKAGE == '%s'", packageName);
	}
}
