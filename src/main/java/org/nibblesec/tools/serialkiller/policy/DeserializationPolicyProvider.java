package org.nibblesec.tools.serialkiller.policy;

import org.nibblesec.tools.serialkiller.policy.rules.DeserializationPolicyRule;
import org.nibblesec.tools.serialkiller.violationhandler.ViolationHandler;

/**
 * Interface for providers of deserialization policies.
 * 
 * @author Wolfgang Ettlinger
 *
 */
public interface DeserializationPolicyProvider {
	Configuration retrieve();
	
	public final static class Configuration{
		private Iterable<DeserializationPolicyRule> blacklistRules;
		private Iterable<DeserializationPolicyRule> whitelistRules;
		private ViolationHandler violationHandler;
		
		public ViolationHandler getViolationHandler() {
			return violationHandler;
		}
		
		void setViolationHandler(ViolationHandler violationHandler) {
			this.violationHandler = violationHandler;
		}

		public Iterable<DeserializationPolicyRule> getWhitelistRules() {
			return whitelistRules;
		}

		void setWhitelistRules(Iterable<DeserializationPolicyRule> whitelistRules) {
			this.whitelistRules = whitelistRules;
		}

		public Iterable<DeserializationPolicyRule> getBlacklistRules() {
			return blacklistRules;
		}

		void setBlacklistRules(Iterable<DeserializationPolicyRule> blacklistRules) {
			this.blacklistRules = blacklistRules;
		}
	}
}
