package cydiasubstrate.hooktools;

import java.lang.reflect.Method;

import android.util.Log;
import hook.android.build;
import hook.android.smsManager;
import hook.android.telephonyManager;
import hook.java.cipher;
import hook.java.stringBuilder;

import com.saurik.substrate.MS;

public class MyApplication implements MS.ClassLoadHook { 
	private static MyApplication MyApplication_Instance;

	public MyApplication() {
		super();
	}
	public static void hook(String application)
	{
		MS.hookClassLoad( application,	new MyApplication() );
	}


	@SuppressWarnings("unchecked")
	public void classLoaded(Class<?> MyApplication) {
		Log.i("Fhook", "hook_Application start!");
		cipher.hook();
		stringBuilder.hook();
		build.hook();
		smsManager.hook();
		telephonyManager.hook();
		Log.i("Fhook", "hook_Application end!");
	}

}