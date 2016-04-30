package cydiasubstrate.hooktools;

import android.util.Log;

public class Initialize {
	public static void initialize() {
		Log.v("Fhook", "java_hook start!");
		//com.tencent.mm.app.MMApplication 
		MyApplication.hook("com.tencent.mm.app.MMApplication");
		Log.v("Fhook", "java_hook end!");
	}
}
