package crypto;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;

public class FileHelper {
	
	public void writeBytes(String filename, byte[] data) {
		try {
			FileOutputStream out = new FileOutputStream(filename);
			out.write(data);
			out.close();
		} catch (IOException e) {
			System.out.println("Error writing file: "+filename);
		}
	}
	
	public BufferedInputStream openFile(String filename) {
		try {
			FileInputStream fis = new FileInputStream(filename);
			BufferedInputStream bis = new BufferedInputStream(fis);
			return bis;
		}
		catch (IOException e) {
			System.out.println("Error reading file: "+filename+" - exiting");
			System.exit(1);
			return null;
		}
	}

	public String readLine(String filename) {
		try {
			FileInputStream fis = new FileInputStream(filename);
			 
			//Construct BufferedReader from InputStreamReader
			BufferedReader br = new BufferedReader(new InputStreamReader(fis));
		 
			String file =  br.readLine();
			
			br.close();
			return file;
		}
		catch (IOException e) {
			System.out.println("Error reading file: "+filename+" - exiting");
			System.exit(1);
			return null;
		}
	}
}
