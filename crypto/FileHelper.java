package crypto;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * @author alex
 * Implements some file handling functions so that they can be shared among different classes
 */
public class FileHelper {
	private LibCrypto lib;
	
	public FileHelper() {
		lib = new LibCrypto();
	}
		
	/**
	 * @param filename
	 * @param data
	 * Writes the contents specified by data into a file specified by filename 
	 */
	public void writeBytes(String filename, byte[] data) {
		try {
			FileOutputStream out = new FileOutputStream(filename);
			out.write(data);
			out.close();
		} catch (IOException e) {
			lib.exit("Error writing file: "+filename+" - exiting", e);
		}
	}
	
	/**
	 * @param filename
	 * @return
	 * Opens a file and returns the BufferedInputStream
	 */
	public BufferedInputStream openFile(String filename) {
		try {
			FileInputStream fis = new FileInputStream(filename);
			BufferedInputStream bis = new BufferedInputStream(fis);
			return bis;
		}
		catch (IOException e) {
			lib.exit("Error opening file: "+filename+" - exiting", e);
			return null;
		}
	}

	/**
	 * @param filename
	 * @return
	 * Reads the first line of the specified file
	 */
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
			lib.exit("Error reading file: "+filename+" - exiting", e);
			return null;
		}
	}
}
