package org.nibblesec.tools.serialkiller;

/**
 * Describes which ruleset of a deserialization policy was violated.
 * 
 * @author Wolfgang Ettlinger
 *
 */
public enum ViolationType {
	Blacklist("Class matches blacklist"),
	NotInWhitelist("Class not in whitelist");
	
	private String description;
	
	private ViolationType(String description) {
		this.description = description;
	}
	
	public String getDescription() {
		return description;
	}
}