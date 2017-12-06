package org.nibblesec.tools.serialkiller.policy.rules;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.nibblesec.tools.serialkiller.util.ClassDescriptor;

public class IsClass implements DeserializationPolicyRule {
	private final Set<ClassDescriptor> classes;
	
	private IsClass() {
		this.classes = new HashSet<>();
	}
	
	public static IsClass fromClassDescriptors(Collection<ClassDescriptor> classes) {
		IsClass res = new IsClass();
		res.classes.addAll(classes);
		return res;
	}
	
	public static IsClass fromClassDescriptors(ClassDescriptor... classes) {
		return fromClassDescriptors(Arrays.asList(classes));
	}
	
	public static IsClass fromClasses(Collection<Class<?>> classes) {
		IsClass res = new IsClass();
		for(Class<?> clz : classes){
			res.classes.add(new ClassDescriptor(clz));
		}
		return res;
	}
	
	public static IsClass fromClasses(Class<?>... classes) {
		return fromClasses(Arrays.asList(classes));
	}
	
	public static IsClass fromClassNames(Collection<String> classNames) {
		IsClass res = new IsClass();
		for(String className : classNames){
			res.classes.add(new ClassDescriptor(className));
		}
		return res;
	}
	
	public static IsClass fromClassNames(String... classNames) {
		return fromClassNames(Arrays.asList(classNames));
	}
	
	@Override
	public boolean matches(Class<?> clz) {
		return this.classes.contains(new ClassDescriptor(clz));
	}

	@Override
	public String describe() {
		return String.format("IN (%s)", 
				String.join(",", (String[]) classes.stream().map(c -> "'"+ c.toString() + "'").toArray()));
	}
}
