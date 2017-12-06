package org.nibblesec.tools.serialkiller.policy.rules;

import static java.util.Objects.requireNonNull;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MatchesPattern implements Iterable<Pattern>, DeserializationPolicyRule {
	private final List<Pattern> patterns;

	private MatchesPattern() {
		this.patterns = new ArrayList<Pattern>();
	}
	
	public MatchesPattern(List<String> regExps) {
		this();
		
		requireNonNull(regExps, "regExps");
		
		for (String regex : regExps) {
			addPattern(regex);
		}
	}
	
	public MatchesPattern(final String... regExps) {
		this(Arrays.asList(regExps));
	}
	
	public synchronized void addPattern(String regExp) {
		this.patterns.add(Pattern.compile(regExp));
	}

	public List<Pattern> getPatterns(){
		return patterns;
	}
	
	@Override
	public Iterator<Pattern> iterator() {
		return new Iterator<Pattern>() {
			int index = 0;

			@Override
			public boolean hasNext() {
				return index < patterns.size();
			}

			@Override
			public Pattern next() {
				return patterns.get(index++);
			}

			@Override
			public void remove() {
				throw new UnsupportedOperationException("remove");
			}
		};
	}

	@Override
	public String toString() {
		return Arrays.toString(patterns.toArray());
	}

	@Override
	public boolean matches(Class<?> clz) {
		for(Pattern p : patterns) {
			Matcher m = p.matcher(clz.getName());
			if(m.matches()) {
				return true;
			}
		}
		
		return false;
	}

	@Override
	public String describe() {
		return String.format("MATCHES ANY (%s)", 
				String.join(",", patterns.stream().map(p -> "'"+ p.pattern() + "'").toArray(String[]::new)));
	}
}
