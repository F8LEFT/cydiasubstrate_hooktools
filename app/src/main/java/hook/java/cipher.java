package hook.java;

import java.lang.reflect.Method;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import android.util.Log;
import tools.statckTrace;

import com.saurik.substrate.MS;

public class cipher implements MS.ClassLoadHook
{
	private static cipher Cipher_Instance;

	public cipher( )
	{
		super( );
	}

	public static void hook()
	{
		MS.hookClassLoad("javax.crypto.Cipher", Cipher_Instance.getInstance());
	}
	
	public static cipher getInstance( )
	{
		if ( Cipher_Instance == null )
		{
			Cipher_Instance = new cipher( );
		}
		return Cipher_Instance;
	}

	@SuppressWarnings( "unchecked" )
	public void classLoaded( Class< ? > clazz )
	{
//------------------------------------------------------------------------------init
		Method init=null;
		try
		{
			init = clazz.getMethod( "init", new Class[]{int.class,Key.class,AlgorithmParameterSpec.class} );
		}
		catch ( Exception e )
		{
			init = null;
			e.printStackTrace( );
		}
		if ( init != null )
		{
			final MS.MethodPointer initold = new MS.MethodPointer( );
			MS.hookMethod( clazz, init, new MS.MethodHook( )
			{
				public Object invoked( Object arg0, Object... arg1 ) throws Throwable
				{
					byte[] key = ((SecretKey)arg1[1]).getEncoded() ;
					byte[] iv =  ((IvParameterSpec)arg1[2]).getIV();
					Log.i("Fhook", "hook_Cipher_doFinal_key" + Arrays.toString((byte[])key) );
					Log.i("Fhook", "hook_Cipher_doFinal_iv" + Arrays.toString((byte[])iv) );
					statckTrace.LogStatckTrace("hook_Cipher_StatckTrace");
					return initold.invoke( arg0, arg1 );
				}
			}, initold );
		}
//------------------------------------------------------------------------------doFinal
		Method doFinal;
		try
		{
			doFinal = clazz.getMethod( "doFinal", new Class[]{byte[].class} );
		}
		catch ( Exception e )
		{
			doFinal = null;
			e.printStackTrace( );
		}
		if(doFinal != null){
			final MS.MethodPointer doFinalold = new MS.MethodPointer( );
			MS.hookMethod( clazz, doFinal, new MS.MethodHook( )
			{
				public Object invoked( Object arg0, Object... arg1 ) throws Throwable
				{
					byte[] result = (byte[]) doFinalold.invoke( arg0, arg1 );
					Log.i("Fhook", "hook_Cipher_doFinal_data" + Arrays.toString((byte[])arg1[0]) );
					Log.i("Fhook", "hook_Cipher_doFinal_result" + Arrays.toString(result) );
					statckTrace.LogStatckTrace("hook_Cipher_StatckTrace");
					return result;
				}
			}, doFinalold );
		}
		
	}
}
