/*
 * $Id: $
 */
package org.microsoft.security.ntlm;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * a.k.a. The "ObjectMolester"
 * <p/>
 * This class is used to access a method or field of an object no
 * matter what the access modifier of the method or field.  The syntax
 * for accessing fields and methods is out of the ordinary because this
 * class uses reflection to peel away protection.
 * <p/>
 * Here is an example of using this to access a private member.
 * <code>resolveName</code> is a private method of <code>Class</code>.
 * <p/>
 * <pre>
 * Class c = Class.class;
 * System.out.println(
 *      PrivilegedAccessor.invokeMethod( c,
 *                                       "resolveName",
 *                                       "/net/iss/common/PrivilegeAccessor" ) );
 * </pre>
 *
 * @author Charlie Hubbard (chubbard@iss.net)
 * @author Prashant Dhokte (pdhokte@iss.net)
 */

public class PrivilegedAccessor {

    public static Object createObject(Class clas, Class[] parameterTypes, Object[] parameters) throws IllegalAccessException, InvocationTargetException, InstantiationException, NoSuchMethodException {
        Constructor constructor = clas.getConstructor(parameterTypes);
        constructor.setAccessible(true);
        Object object = constructor.newInstance(parameters);
        return object;
    }

    public static Object createObject(String className, Class[] parameterTypes, Object[] parameters) throws IllegalAccessException, InvocationTargetException, InstantiationException, NoSuchMethodException, ClassNotFoundException {
        Class clas = Class.forName(className);
        Constructor constructor = clas.getConstructor(parameterTypes);
        constructor.setAccessible(true);
        Object object = constructor.newInstance(parameters);
        return object;
    }

    public static Object callMethod(Object object, String methodName, Class[] parameterTypes, Object[] parameters) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        Method method = getMethod(object, methodName, parameterTypes);
        Object result = method.invoke(object, parameters);
        return result;
    }

    /**
     * Gets the value of the named field and returns it as an object.
     *
     * @param instance  the object instance
     * @param fieldName the name of the field
     * @return an object representing the value of the field
     */
    public static Object getValue(Object instance, String fieldName) throws IllegalAccessException, NoSuchFieldException {
        Field field = getField(instance.getClass(), fieldName);
        field.setAccessible(true);
        return field.get(instance);
    }

    /**
     * Gets the value of the named field and returns it as an object.
     *
     * @param instanceClassName the object instanceClass
     * @param fieldName     the name of the field
     * @return an object representing the value of the field
     */
    public static Object getStaticValue(String instanceClassName, String fieldName) throws IllegalAccessException, NoSuchFieldException, ClassNotFoundException {
        Class instanceClass = Class.forName(instanceClassName);
        Field field = getField(instanceClass, fieldName);
        field.setAccessible(true);
        return field.get(null);
    }

    /**
     * Gets the value of the named field and returns it as an object.
     *
     * @param instanceClass the object instanceClass
     * @param fieldName     the name of the field
     * @return an object representing the value of the field
     */
    public static Object getStaticValue(Class instanceClass, String fieldName) throws IllegalAccessException, NoSuchFieldException {
        Field field = getField(instanceClass, fieldName);
        field.setAccessible(true);
        return field.get(null);
    }

    /**
     * Sets the value of the named field and returns it as an object.
     *
     * @param instance  the object instanceClass
     * @param fieldName the name of the field
     */
    public static void setValue(Object instance, String fieldName, Object value) throws IllegalAccessException, NoSuchFieldException {
        Class instanceClass = instance.getClass();
        Field field = getField(instanceClass, fieldName);
        field.setAccessible(true);
        field.set(instance, value);
    }

    /**
     * Sets the value of the named field and returns it as an object.
     *
     * @param instanceClass the object instanceClass
     * @param fieldName     the name of the field
     */
    public static void setStaticValue(Class instanceClass, String fieldName, Object value) throws IllegalAccessException, NoSuchFieldException {
        Field field = getField(instanceClass, fieldName);
        field.setAccessible(true);
        field.set(null, value);
    }

    /**
     * Calls a method on the given object instance with the given argument.
     *
     * @param instance   the object instance
     * @param methodName the name of the method to invoke
     * @param arg        the argument to pass to the method
     * @see PrivilegedAccessor#invokeMethod(Object,String,Object[])
     */
    public static Object invokeMethod(Object instance, String methodName, Object arg) throws NoSuchMethodException,
            IllegalAccessException, InvocationTargetException {
        Object[] args = new Object[1];
        args[0] = arg;
        return invokeMethod(instance, methodName, args);
    }

    /**
     * Calls a method on the given object instance with the given arguments.
     *
     * @param instance   the object instance
     * @param methodName the name of the method to invoke
     * @param args       an array of objects to pass as arguments
     * @see PrivilegedAccessor#invokeMethod(Object,String,Object)
     */
    public static Object invokeMethod(Object instance, String methodName, Object[] args) throws NoSuchMethodException,
            IllegalAccessException, InvocationTargetException {
        Class[] classTypes = null;
        if (args != null) {
            classTypes = new Class[args.length];
            for (int i = 0; i < args.length; i++) {
                if (args[i] != null)
                    classTypes[i] = args[i].getClass();
            }
        }
        return getMethod(instance, methodName, classTypes).invoke(instance, args);
    }

    /**
     * Calls a method on the given object instance with the given arguments.
     *
     * @param instance   the object instance
     * @param methodName the name of the method to invoke
     * @param args       an array of objects to pass as arguments
     * @see PrivilegedAccessor#invokeMethod(Object,String,Object)
     */
    public static Object invokeMethod(Object instance, String methodName, Class[] classTypes, Object[] args) throws NoSuchMethodException,
            IllegalAccessException, InvocationTargetException {
        return getMethod(instance, methodName, classTypes).invoke(instance, args);
    }

    /**
     * @param instance   the object instance
     * @param methodName the
     */
    public static Method getMethod(Object instance, String methodName, Class[] classTypes) throws NoSuchMethodException {
        Method accessMethod = getMethod(instance.getClass(), methodName, classTypes);
        accessMethod.setAccessible(true);
        return accessMethod;
    }

    /**
     * Return the named field from the given class.
     */
    private static Field getField(Class thisClass, String fieldName) throws NoSuchFieldException {
        if (thisClass == null)
            throw new NoSuchFieldException("Invalid field : " + fieldName);
        try {
            return thisClass.getDeclaredField(fieldName);
        }
        catch (NoSuchFieldException e) {
            return getField(thisClass.getSuperclass(), fieldName);
        }
    }

    /**
     * Return the named method with a method signature matching classTypes
     * from the given class.
     */
    private static Method getMethod(Class thisClass, String methodName, Class[] classTypes) throws NoSuchMethodException {
        if (thisClass == null)
            throw new NoSuchMethodException("Invalid method : " + methodName);
        try {
            return thisClass.getDeclaredMethod(methodName, classTypes);
        }
        catch (NoSuchMethodException e) {
            return getMethod(thisClass.getSuperclass(), methodName, classTypes);
        }
    }
}
