/*
 * SerialKiller.java
 *
 * Copyright (c) 2015-2016 Luca Carettoni
 *
 * SerialKiller is an easy-to-use look-ahead Java deserialization library
 * to secure application from untrusted input. When Java serialization is
 * used to exchange information between a client and a server, attackers
 * can replace the legitimate serialized stream with malicious data.
 * SerialKiller inspects Java classes during naming resolution and allows
 * a combination of blacklisting/whitelisting to secure your application.
 *
 * Dual-Licensed Software: Apache v2.0 and GPL v2.0
 */
package org.nibblesec.tools;

import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.logging.Logger;

import org.nibblesec.tools.serialkiller.ViolationType;
import org.nibblesec.tools.serialkiller.policy.ConfigurationFileLoader;
import org.nibblesec.tools.serialkiller.policy.DeserializationPolicyProvider;
import org.nibblesec.tools.serialkiller.policy.StaticDeserializationPolicyProvider;
import org.nibblesec.tools.serialkiller.policy.DeserializationPolicyProvider.Configuration;
import org.nibblesec.tools.serialkiller.policy.rules.DeserializationPolicyRule;

public class SerialKiller extends ObjectInputStream {
	// TODO: Should SEVERE logs be WARNINGS?
    // TODO: Does it make sense to use JDK logging, when the project depends on commons-logging?
    private static final Logger LOGGER = Logger.getLogger(SerialKiller.class.getName());
    
    private DeserializationPolicyProvider policyProvider;
    
    public SerialKiller(final InputStream inputStream, final DeserializationPolicyProvider policyProvider) throws IOException {
    	super(inputStream);
    	this.policyProvider = policyProvider;
    }
    
    public SerialKiller(final InputStream inputStream, final Configuration config) throws IOException {
    	this(inputStream, new StaticDeserializationPolicyProvider(config));
    }
    
    /**
     * SerialKiller constructor, returns instance of ObjectInputStream.
     *
     * @param inputStream The original InputStream, used by your service to receive serialized objects
     * @param configFile The location of the config file (absolute path)
     * @throws java.io.IOException File I/O exception
     * @throws IllegalStateException Invalid configuration exception
     */
    public SerialKiller(final InputStream inputStream, final String configFile) throws IOException {
        this(inputStream, ConfigurationFileLoader.retrieve(configFile));
    }

    @Override
    protected Class<?> resolveClass(final ObjectStreamClass serialInput) throws IOException, ClassNotFoundException {
        Class<?> clazz = super.resolveClass(serialInput);
        checkClass(clazz);
        
        return clazz;
    }
	
	public void setPolicyProvider(DeserializationPolicyProvider ruleProvider) {
		this.policyProvider = ruleProvider;
	}
	
	private final void checkClass(Class<?> clazz) throws InvalidClassException {
		final Configuration config = policyProvider.retrieve();
		
		for(DeserializationPolicyRule blacklistRule : config.getBlacklistRules()){
			if(blacklistRule.matches(clazz)){
				config.getViolationHandler().onViolation(clazz, ViolationType.Blacklist, blacklistRule);
			}
		}
		
		for(DeserializationPolicyRule whitelistRule : config.getWhitelistRules()){
			if(whitelistRule.matches(clazz)){
				return;
			}
		}
		
		config.getViolationHandler().onViolation(clazz, ViolationType.NotInWhitelist, null);
	}
}
