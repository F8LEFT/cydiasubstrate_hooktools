package tools;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import android.util.Log;

public class file {
	public static String readTxtFile(String filePath )
	{
		File f = new File( filePath );
		if ( !f.exists( ) )
		{
			Log.e( "readFile", "error con't find the file!" + filePath );
		}
		StringBuilder sb = new StringBuilder( );
		try
		{
			FileInputStream fs = new FileInputStream( new File( filePath ) );
			BufferedReader reader = new BufferedReader( new InputStreamReader( ( ( InputStream ) fs ) ) );
			String v6;
			while ( ( v6 = reader.readLine( ) ) != null )
			{
				sb.append( v6 );
			}
			reader.close( );
			fs.close( );
		}
		catch ( IOException v2 )
		{
		}
		return sb.toString( );
	}
}
