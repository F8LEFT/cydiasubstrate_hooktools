package hook.android;


import java.lang.reflect.Method;
import android.util.Log;
import tools.statckTrace;

import com.saurik.substrate.MS;

public class telephonyManager implements MS.ClassLoadHook
{
	private static telephonyManager TelephonyManager_Instance;

	public telephonyManager( )
	{
		super( );
	}
	
	public static void hook(){
		MS.hookClassLoad( "android.telephony.TelephonyManager",getInstance());
	}
	
	public static telephonyManager getInstance( )
	{
		if ( TelephonyManager_Instance == null )
		{
			TelephonyManager_Instance = new telephonyManager( );
		}
		return TelephonyManager_Instance;
	}

	@SuppressWarnings( "unchecked" )
	public void classLoaded( Class< ? > arg0 )
	{
		Method hookimei;
		try
		{
			hookimei = arg0.getMethod( "getDeviceId", null );
		}
		catch (Exception e )
		{
			hookimei = null;
			e.printStackTrace( );
		}
		if ( hookimei != null )
		{
			final MS.MethodPointer old = new MS.MethodPointer( );
			MS.hookMethod( arg0, hookimei, new MS.MethodHook( )
			{
				public Object invoked( Object arg0, Object... arg1 ) throws Throwable
				{
					String imei = ""; 
					imei = ( String ) old.invoke( arg0, arg1 );
//					imei = "352621061639586";
					Log.i( "hook_imei", imei );
					statckTrace.LogStatckTrace("hook_imsi_StatckTrace");
					return imei;
				}
			}, old );
		}
		Method hookimsi;
		try
		{
			hookimsi = arg0.getMethod( "getSubscriberId", null );
		}
		catch (Exception e )
		{
			hookimsi = null;
			e.printStackTrace( );
		}
		if ( hookimsi != null )
		{
			final MS.MethodPointer old = new MS.MethodPointer( );
			MS.hookMethod( arg0, hookimsi, new MS.MethodHook( )
			{
				public Object invoked( Object arg0, Object... arg1 ) throws Throwable
				{
					String imsi = "";
					imsi = ( String ) old.invoke( arg0, arg1 );
					Log.i( "hook_imsi", imsi );
					statckTrace.LogStatckTrace("hook_imsi_StatckTrace");
					return imsi;
				}
			}, old );
		}
		
		
	}
}
