package hook.java;

import java.lang.reflect.Method;

import android.util.Log;

import com.saurik.substrate.MS;

public class stringBuilder implements MS.ClassLoadHook
{
	private static stringBuilder StringBuilder_Instance = null;

	public stringBuilder( )
	{
		super( );
	}

	public static void hook(){
		MS.hookClassLoad( "java.lang.StringBuilder",getInstance( ));
	}
	
	public static stringBuilder getInstance( )
	{
		if ( StringBuilder_Instance == null )
		{
			StringBuilder_Instance = new stringBuilder( );
		}
		return StringBuilder_Instance;
	}

	@SuppressWarnings( "unchecked" )
	public void classLoaded( Class< ? > StringBuilder_class )
	{
		Method hookstring;
		try
		{
			hookstring = StringBuilder_class.getMethod( "toString", null );
		}
		catch ( Exception e )
		{
			hookstring = null;
			e.printStackTrace( );
		}	
		if ( hookstring != null )
		{
			final MS.MethodPointer old = new MS.MethodPointer( );
			MS.hookMethod( StringBuilder_class, hookstring, new MS.MethodHook( )
			{
				public Object invoked( Object arg0, Object... arg1 ) throws Throwable
				{
					String str = ( String ) old.invoke( arg0, arg1 );
					if(str.length()<1023){
						Log.i( "Fhook", "hook_StringBuilder_toString" + str );
					}else{						
						Log.i("Fhook", "hook_StringBuilder_toString_Multi-section" + "start" );
						int length= 1023;
						int i = 0;
						for(;i<str.length()&& length < str.length() ;i+=1023,length+=1023){
							Log.i("Fhook", "hook_StringBuilder_toString" + str.substring(i,length) );
						}
						Log.i("Fhook", "hook_StringBuilder_toString" + str.substring(i) );
						Log.i("Fhook", "hook_StringBuilder_toString_Multi-section" + "end" );
					}
					return str;
				}
			}, old );
		}
	}
}
