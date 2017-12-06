package org.nibblesec.tools;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Iterator;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.junit.Test;
import org.nibblesec.tools.serialkiller.policy.rules.MatchesPattern;

/**
 * PatternListTest
 */
public class MatchesPatternTest {
    @Test(expected = NullPointerException.class)
    public void testCreateNull() {
        new MatchesPattern((String[]) null);
    }

    @Test(expected = PatternSyntaxException.class)
    public void testCreateBadPattern() {
    	new MatchesPattern("(");
    }

    @Test
    public void testCreateEmpty() {
    	MatchesPattern list = new MatchesPattern(new String[0]);

        Iterator<Pattern> iterator = list.iterator();
        assertFalse(iterator.hasNext());
    }

    @Test
    public void testCreateSingle() {
    	MatchesPattern list = new MatchesPattern("a");

        Iterator<Pattern> iterator = list.iterator();
        assertTrue(iterator.hasNext());
        Pattern pattern = iterator.next();
        assertNotNull(pattern);
        assertEquals("a", pattern.pattern());
        assertFalse(iterator.hasNext());
    }

    @Test
    public void testCreateSequence() {
        String[] patterns = {"a", "b", "c"};
        MatchesPattern list = new MatchesPattern(patterns);

        int index = 0;
        for (Pattern pattern : list) {
            assertNotNull(pattern);
            assertEquals(patterns[index++], pattern.pattern());
        }

        assertEquals(3, index);
    }

    @Test
    public void testCreateSafeArgs() {
        String[] patterns = {"1", "2"};
        MatchesPattern list = new MatchesPattern(patterns);
        patterns[1] = "three";

        int index = 0;
        for (Pattern pattern : list) {
            assertEquals(String.valueOf(++index), pattern.pattern());
        }

        assertEquals(2, index);
    }
}