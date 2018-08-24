import java.math.BigInteger;
import java.security.MessageDigest;
import java.io.ObjectOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Random;

public class MyKeyGen {
    public static void main(String [] args) {
        BigInteger p = BigInteger.probablePrime(512, new Random());
        BigInteger q = BigInteger.probablePrime(512, new Random());
        BigInteger n = p.multiply(q);
        BigInteger phiN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger e = BigInteger.probablePrime(512, new Random());
        while (e.compareTo(BigInteger.ONE) <= 0 || e.compareTo(phiN) >= 0 || !e.gcd(phiN).equals(BigInteger.ONE)) {
            e = e.nextProbablePrime();
        }
        BigInteger d = e.modInverse(phiN);
        try {
            saveKeys(e, d, n);
        }
        catch (IOException ex) {}
    }
    public static void saveKeys(BigInteger e, BigInteger d, BigInteger n) throws IOException{
        FileOutputStream pub = new FileOutputStream("pubkey.rsa");
        ObjectOutputStream oos = new ObjectOutputStream(pub);
        oos.writeObject(e);
        oos.writeObject(n);

        FileOutputStream priv = new FileOutputStream("privkey.rsa");
        ObjectOutputStream ons = new ObjectOutputStream(priv);
        ons.writeObject(d);
        ons.writeObject(n);
    }
}