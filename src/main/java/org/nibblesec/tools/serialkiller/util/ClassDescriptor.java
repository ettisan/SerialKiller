package org.nibblesec.tools.serialkiller.util;

/**
 * Describes a class. Unlike java.lang.Class this class does not require the
 * described class to be present in the classpath.
 * 
 * @author Wolfgang Ettlinger
 *
 */
public class ClassDescriptor {
	private String clzPackage;
	private String clzShortName;
	
	public ClassDescriptor(String clzPackage, String clzShortName) {
		this.clzShortName = clzShortName;
		this.clzPackage = clzPackage;
	}
	
	public ClassDescriptor(String clzName){
		int seperatorOffset = clzName.lastIndexOf('.');
		this.clzShortName = clzName.substring(seperatorOffset+1);
		this.clzPackage = clzName.substring(0, seperatorOffset);
	}
	
	public ClassDescriptor(Class<?> clz){
		this.clzShortName = clz.getSimpleName();
		Package pkg = clz.getPackage();
		if(pkg == null) {
			this.clzPackage = "";
		}else {
			this.clzPackage = pkg.getName();
		}
	}
	
	public boolean matches(Class<?> clz){
		return new ClassDescriptor(clz).equals(this);
	}
	
	@Override
	public boolean equals(Object other) {
		boolean result = false;
	    if (other instanceof ClassDescriptor) {
	    	ClassDescriptor that = (ClassDescriptor) other;
	        result = this.clzPackage.equals(that.clzPackage) && this.clzShortName.equals(that.clzShortName);
	    }
	    return result;
	}
	
	@Override
	public String toString() {
		return String.format("%s.%s", clzPackage, clzShortName);
	}
}
