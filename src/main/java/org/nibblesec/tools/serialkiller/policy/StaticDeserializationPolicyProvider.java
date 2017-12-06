package org.nibblesec.tools.serialkiller.policy;

/**
 * Deserialization policy provider that always returns a static deserialization
 * policy configuration.
 * 
 * @author Wolfgang Ettlinger
 *
 */
public class StaticDeserializationPolicyProvider implements DeserializationPolicyProvider {
	private final Configuration configuration;
	
	public StaticDeserializationPolicyProvider(final Configuration configuration) {
		this.configuration = configuration;
	}
	
	@Override
	public Configuration retrieve() {
		return configuration;
	}

}
