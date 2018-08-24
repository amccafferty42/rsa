import java.io.FileNotFoundException;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.FileSystemNotFoundException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MySign {
    public static void main (String [] args) {
        String filename = "";
        char mode = '\0';
        try {
            mode = args[0].charAt(0);
            filename = args[1];
        }
        catch (ArrayIndexOutOfBoundsException e) {
            System.out.println("Format: java MySign [\"v\"/\"s\"] [filename]");
            System.exit(0);
        }

        if (mode == 's') {
            signFile(filename);
        }
        else if (mode == 'v') {
            verifySignature(filename);
        }
        else {
            System.out.println("Format: java MySign [\"v\"/\"s\"] [filename]");
            System.exit(0);            
        }
    }

    private static int signFile(String filename) {	
		try {
			BigInteger decrypted, d, n;
			byte [] data, hash;
			
			Path filepath = Paths.get(filename);
			data = Files.readAllBytes(filepath);
			
			MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
			sha256.update(data);
			hash = sha256.digest();
			
			FileInputStream pub = new FileInputStream("privkey.rsa");
			ObjectInputStream ois = new ObjectInputStream(pub);
			
			d = (BigInteger)ois.readObject();
			n = (BigInteger)ois.readObject();
			ois.close();
			decrypted = new BigInteger(1, hash).modPow(d, n);
			
			return writeFile(filename, data, decrypted);
		}
		catch (FileNotFoundException fnfe) {
			System.out.println("Error: privkey.rsa was not found in this directory.");
			return 1;
		}
        catch (Exception ex) {
            System.out.println("There was a problem reading the file.");
            return 1;
        }
    }

    private static int writeFile(String filename, byte [] data, BigInteger decrypted) {
        try {
			String signedFilename = filename.concat(".signed");	
			FileOutputStream decryptedFile = new FileOutputStream(signedFilename);
			ObjectOutputStream decryptedWriter = new ObjectOutputStream(decryptedFile);
			
			decryptedWriter.writeObject(data);
			decryptedWriter.writeObject(decrypted);
			decryptedWriter.close();
			
			System.out.println("Successfully signed. The signed file has been saved as "+signedFilename+".");
			return 0;
		}
		catch (IOException ioe) {
			System.out.println("Error: There was an error writing the signed file.");
			return 1;
		}      
    }

    private static int verifySignature(String filename) {	
		try {
			byte[] original;
			BigInteger decrypted;
			
			FileInputStream signedFile = new FileInputStream(filename);
			ObjectInputStream signedReader = new ObjectInputStream(signedFile);
			
			original = (byte[])signedReader.readObject();
			decrypted = (BigInteger)signedReader.readObject();
			signedReader.close();
			
			return readPublicKey(original, decrypted, filename);
		}
		catch (FileNotFoundException fnfe) {
			System.out.println("Error: pubkey.rsa was not found in this directory.");
			return 1;
		}
		catch (ClassNotFoundException cnfe) {
			System.out.println("Error: The object that was read could not be associated with a class.");
			return 1;
		}
		catch (IOException ioe) {
			System.out.println("Error: There was an problem reading the file.");
			return 1;
		}
		
	}
	
	private static int readPublicKey(byte[] original, BigInteger decryptedHash, String filename) {
		try {
			BigInteger e, n, encrypted, originalHash;
			byte[] hashedData;
			
			MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
			sha256.update(original);
			hashedData = sha256.digest();
			originalHash = new BigInteger(1, hashedData);
			
			FileInputStream pub = new FileInputStream("pubkey.rsa");
			ObjectInputStream ois = new ObjectInputStream(pub);
			
			e = (BigInteger)ois.readObject();	
			n = (BigInteger)ois.readObject();
			ois.close();
			encrypted = decryptedHash.modPow(e, n);

            if (originalHash.equals(encrypted))
                System.out.println("The signature of "+filename+" is valid.");
            else
                System.out.println("The signature of "+filename+" is invalid.");
			return 0;
		}
		catch (NoSuchAlgorithmException nsae) {
			System.out.println("Error: The requested algorithm does not exist.");
			return 1;
		}
		catch (FileNotFoundException fnfe) {
			System.out.println("Error: pubkey.rsa was not found in this directory.");	
			return 1;
		}
		catch (ClassNotFoundException cnfe) {
			System.out.println("Error: The object that was read could not be associated with a class.");
			return 1;
		}
		catch (IOException ioe) {
			System.out.println("Error: There was an problem reading the file.");	
			return 1;
		}
	}
}