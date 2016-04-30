package tools;

import android.util.Log;

public class statckTrace {
	public static void LogStatckTrace(String tag){
		StackTraceElement[] ste= new Throwable().getStackTrace();
		Log.i( tag, "start");
		for(int i=3;i<ste.length;i++)
			Log.i( tag, ste[i].toString() );
		Log.i( tag, "end" );
	}
}
