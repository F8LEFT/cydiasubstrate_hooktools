package hook.android;

import java.lang.reflect.Field;

public class build {

	public static void hook(){
		setBRAND("wm_qd");
		setMODEL("QQgroup_456853837");
	}
	
	
	public static void setBRAND(String brand){
		setStaticObjectField( "android.os.Build","BRAND",brand);
	}
	public static void setMODEL(String model){
		setStaticObjectField( "android.os.Build","MODEL",model);
	}
	
	public static boolean setStaticObjectField(String className, String fieldName, Object data )
	{
		try
		{
			Class c = Class.forName( className );
			Field f = c.getDeclaredField( fieldName );
			f.setAccessible( true );
			f.set( className, data );
		}
		catch (Exception e )
		{
			e.printStackTrace( );
			return false;
		}
		return true;
	}
}
