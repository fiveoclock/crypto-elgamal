package crypto;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;

public class FileHelper {
	
	public void writeBytes(String name, byte[] data) {
		try {
			FileOutputStream out = new FileOutputStream(name);
			out.write(data);
			out.close();
		} catch (IOException e) {
			System.out.println("Error writing file");
		}
	}

	public String readLine(String name) {
		try {
			FileInputStream fis = new FileInputStream(name);
			 
			//Construct BufferedReader from InputStreamReader
			BufferedReader br = new BufferedReader(new InputStreamReader(fis));
		 
			String file =  br.readLine();
			
			br.close();
			return file;
		}
		catch (IOException e) {
			System.out.println("Error writing file");
			return null;
		}
	}
}
