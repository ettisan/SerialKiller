package org.nibblesec.tools.serialkiller.policy;

import static java.util.Objects.requireNonNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;
import java.util.regex.PatternSyntaxException;

import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.XMLConfiguration;
import org.apache.commons.configuration.reloading.FileChangedReloadingStrategy;
import org.nibblesec.tools.serialkiller.policy.rules.DeserializationPolicyRule;
import org.nibblesec.tools.serialkiller.policy.rules.IsClass;
import org.nibblesec.tools.serialkiller.policy.rules.MatchesPattern;
import org.nibblesec.tools.serialkiller.policy.rules.Not;
import org.nibblesec.tools.serialkiller.violationhandler.LogViolationHandler;
import org.nibblesec.tools.serialkiller.violationhandler.ThrowExceptionViolationHandler;

/**
 * Class handling access to configuration files.
 * 
 * @author Wolfgang Ettlinger
 *
 */
public final class ConfigurationFileLoader {
	private static final Logger LOGGER = Logger.getLogger(ConfigurationFileLoader.class.getName());
	
	private static final Map<String, ConfigurationFilePolicyProvider> configs = new ConcurrentHashMap<>();

    public static DeserializationPolicyProvider retrieve(final String configFile) throws IOException {
    	requireNonNull(configFile, "configFile");
    	return configs.computeIfAbsent(configFile, ConfigurationFilePolicyProvider::new);
	}

    static final class ConfigurationFilePolicyProvider implements DeserializationPolicyProvider {
        private final XMLConfiguration xmlConfig;
        private Configuration configuration;

        ConfigurationFilePolicyProvider(final String configPath) {
        	configuration = new Configuration();
            try {
                xmlConfig = new XMLConfiguration(configPath);

                FileChangedReloadingStrategy reloadStrategy = new FileChangedReloadingStrategy();
                reloadStrategy.setRefreshDelay(xmlConfig.getLong("refresh", 6000));
                xmlConfig.setReloadingStrategy(reloadStrategy);
                xmlConfig.addConfigurationListener(event -> init(xmlConfig));

                init(xmlConfig);
            } catch (ConfigurationException | PatternSyntaxException e) {
                throw new IllegalStateException("SerialKiller not properly configured: " + e.getMessage(), e);
            }
        }

        private void init(final XMLConfiguration config) {
			MatchesPattern blacklistRegex = new MatchesPattern(config.getStringArray("blacklist.regexps.regexp"));
        	IsClass blacklistNames = IsClass.fromClassNames(config.getStringArray("blacklist.list.name"));
        	
        	List<DeserializationPolicyRule> blacklistRules = new ArrayList<>();
        	
        	// Enforce SerialKiller's blacklist
        	blacklistRules.add(blacklistNames);
        	blacklistRules.add(blacklistRegex);
        	
        	configuration.setBlacklistRules(blacklistRules);

        	MatchesPattern whitelistRegex = new MatchesPattern(config.getStringArray("whitelist.regexps.regexp"));
        	IsClass whiteListNames = IsClass.fromClassNames(config.getStringArray("whitelist.list.name"));

        	List<DeserializationPolicyRule> whitelistRules = new ArrayList<>();
        	whitelistRules.add(whiteListNames);
        	whitelistRules.add(whitelistRegex);
        	
        	configuration.setWhitelistRules(whitelistRules);
        	
        	if(config.getBoolean("mode.profiling", false)) {
        		configuration.setViolationHandler(new LogViolationHandler());
        	}else {
        		configuration.setViolationHandler(new ThrowExceptionViolationHandler());
        	}
        }

        void reloadIfNeeded() {
            // NOTE: Unfortunately, this will invoke synchronized blocks in Commons Configuration
            xmlConfig.reload();
        }

		@Override
		public Configuration retrieve() {
			reloadIfNeeded();
			
			return configuration;
		}
    }
}
