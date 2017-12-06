package org.nibblesec.tools;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.Iterator;

import org.junit.Test;
import org.nibblesec.tools.serialkiller.policy.ConfigurationFileLoader;
import org.nibblesec.tools.serialkiller.policy.DeserializationPolicyProvider;
import org.nibblesec.tools.serialkiller.policy.DeserializationPolicyProvider.Configuration;
import org.nibblesec.tools.serialkiller.policy.rules.DeserializationPolicyRule;
import org.nibblesec.tools.serialkiller.policy.rules.MatchesPattern;
import org.nibblesec.tools.serialkiller.policy.rules.Not;

/**
 * ConfigurationTest
 */
public class ConfigurationTest {
    @Test(expected = NullPointerException.class)
    public void testCreateNull() throws IOException {
    	ConfigurationFileLoader.retrieve(null);
    }

    @Test(expected = IllegalStateException.class)
    public void testCreateNonExistant() throws IOException {
    	ConfigurationFileLoader.retrieve("/i/am/pretty-sure/this-file/does-not-exist");
    }

    @Test(expected = IllegalStateException.class)
    public void testCreateNonConfig() throws IOException {
        Path tempFile = Files.createTempFile("sk-", ".tmp");
        ConfigurationFileLoader.retrieve(tempFile.toAbsolutePath().toString());
    }

    @Test(expected = IllegalStateException.class)
    public void testCreateBadPattern() throws IOException {
    	ConfigurationFileLoader.retrieve("src/test/resources/broken-pattern.conf");
    }

    private void verifyPatterns(Configuration configuration, String blacklistPattern, String whitelistPattern) {
    	
        Iterator<DeserializationPolicyRule> itw = configuration.getWhitelistRules().iterator();
        itw.next(); // whitelistnames
    	MatchesPattern mp = ((MatchesPattern)(itw.next()));
    	if(whitelistPattern != null) {
    		assertEquals(whitelistPattern, mp.getPatterns().get(0).pattern()); // whitelist regexes
    	}

    	Iterator<DeserializationPolicyRule> itb = configuration.getBlacklistRules().iterator();
    	itb.next(); // blacklist names
    	mp = ((MatchesPattern)(itb.next()));
    	if(blacklistPattern != null) {
    		assertEquals(blacklistPattern, mp.getPatterns().get(0).pattern()); // blacklist regexes
    	}
    }
    
    @Test
    public void testCreateGood() throws IOException {
        Configuration configuration = ConfigurationFileLoader.retrieve("src/test/resources/blacklist-all.conf").retrieve();

        verifyPatterns(configuration, ".*", "java\\.lang\\..*");
    }

    @Test
    public void testReload() throws Exception {
        Path tempFile = Files.createTempFile("sk-", ".conf");
        Files.copy(new File("src/test/resources/blacklist-all-refresh-10-ms.conf").toPath(), tempFile, REPLACE_EXISTING);

        DeserializationPolicyProvider provider = ConfigurationFileLoader.retrieve(tempFile.toAbsolutePath().toString());
        
        Configuration configuration = provider.retrieve();

        verifyPatterns(configuration, ".*", "java\\.lang\\..*");

        Files.copy(new File("src/test/resources/whitelist-all.conf").toPath(), tempFile, REPLACE_EXISTING);
        Files.setLastModifiedTime(tempFile, FileTime.fromMillis(System.currentTimeMillis())); // Commons configuration watches file modified time
        Thread.sleep(12L); // Wait to ensure a reload happens

        configuration = provider.retrieve(); // Trigger reload

        verifyPatterns(configuration, null, ".*");
    }
}