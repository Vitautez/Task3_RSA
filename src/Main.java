import java.io.*;
import java.math.BigInteger;
import java.util.*;

public class Main {


    //GREATES COMMON DIVISOR
    public static BigInteger gcd(BigInteger a, BigInteger b) {
        while (!b.equals(BigInteger.ZERO)) {
            BigInteger temp = b;
            b = a.mod(b);
            a = temp;
        }
        return a;
    }

    //PRIVATE KEY D IS FOUND (USING EXTENDED EUCLIDEAN ALGORITHM)
    public static BigInteger modInverse(BigInteger e, BigInteger phi) {
        BigInteger t = BigInteger.ZERO, newT = BigInteger.ONE;
        BigInteger r = phi, newR = e;

        while (!newR.equals(BigInteger.ZERO)) {
            BigInteger quotient = r.divide(newR);
            BigInteger tempT = t;
            t = newT;
            newT = tempT.subtract(quotient.multiply(newT));
            BigInteger tempR = r;
            r = newR;
            newR = tempR.subtract(quotient.multiply(newR));
        }

        if (r.compareTo(BigInteger.ONE) > 0) throw new ArithmeticException("e is not invertible");
        if (t.compareTo(BigInteger.ZERO) < 0) t = t.add(phi);
        return t;
    }

    //PLAINTEXT TO ASCII NUMBERS
    public static List<BigInteger> stringToAscii(String text) {
        List<BigInteger> asciiList = new ArrayList<>();
        for (char ch : text.toCharArray()) {
            asciiList.add(BigInteger.valueOf((int) ch));
        }
        return asciiList;
    }

    //ASCII TO PLAINTEXT
    public static String asciiToString(List<BigInteger> asciiList) {
        StringBuilder sb = new StringBuilder();
        for (BigInteger b : asciiList) {
            sb.append((char) b.intValue());
        }
        return sb.toString();
    }

    //PLAINTEXT ENCRYPTION
    public static List<BigInteger> encrypt(List<BigInteger> message, BigInteger e, BigInteger n) {
        List<BigInteger> encrypted = new ArrayList<>();
        for (BigInteger m : message) {
            encrypted.add(m.modPow(e, n));
        }
        return encrypted;
    }

    //PLAINTEXT DECRYPTION
    public static List<BigInteger> decrypt(List<BigInteger> ciphertext, BigInteger d, BigInteger n) {
        List<BigInteger> decrypted = new ArrayList<>();
        for (BigInteger c : ciphertext) {
            decrypted.add(c.modPow(d, n));
        }
        return decrypted;
    }

    public static BigInteger[] factorN(BigInteger n) {
        BigInteger i = BigInteger.TWO;
        while (i.compareTo(n.sqrt().add(BigInteger.ONE)) <= 0) {
            if (n.mod(i).equals(BigInteger.ZERO)) {
                return new BigInteger[]{i, n.divide(i)};
            }
            i = i.add(BigInteger.ONE);
        }
        return null;
    }

    //SAVE TO FILE
    public static void saveToFile(String filename, BigInteger n, BigInteger e, List<BigInteger> ciphertext) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename))) {
            writer.write(n + "\n" + e + "\n");
            for (BigInteger c : ciphertext) {
                writer.write(c + "\n");
            }
        }
        System.out.println("Ciphertext and Public Key saved to file: " + filename);
    }

    //READ FROM FILE
    public static Object[] readFromFile(String filename) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            BigInteger n = new BigInteger(reader.readLine());
            BigInteger e = new BigInteger(reader.readLine());
            List<BigInteger> ciphertext = new ArrayList<>();
            String line;
            while ((line = reader.readLine()) != null) {
                ciphertext.add(new BigInteger(line));
            }

            System.out.println("Loaded from file:");
            System.out.println("n = " + n);
            System.out.println("e = " + e);
            System.out.println("Ciphertext from file: " + ciphertext);

            return new Object[]{n, e, ciphertext};
        }
    }

    //START
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        BigInteger p, q;

        //INPUT P
        while (true) {
            System.out.print("Please enter prime number p (not greater than 1000): ");
            p = new BigInteger(scanner.nextLine());
            if (p.compareTo(BigInteger.valueOf(1000)) >= 0) {
                System.out.println("p not greater than 1000.");
            } else if (!p.isProbablePrime(10)) {
                System.out.println("p is not a prime number.");
            } else {
                break;
            }
        }

        //INPUT Q
        while (true) {
            System.out.print("Please enter prime number q (not greater than 1000): ");
            q = new BigInteger(scanner.nextLine());
            if (q.compareTo(BigInteger.valueOf(1000)) >= 0) {
                System.out.println("q must be not greater than 1000.");
            } else if (!q.isProbablePrime(10)) {
                System.out.println("q is not a prime number.");
            } else {
                break;
            }
        }

        //INPUT PLAINTEXT
        System.out.print("Please enter plaintext: ");
        String message = scanner.nextLine();

        //Key Generation
        BigInteger n = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        //Automatically chooses e
        BigInteger e = BigInteger.valueOf(3);
        while (!gcd(e, phi).equals(BigInteger.ONE)) {
            e = e.add(BigInteger.TWO);
        }

        BigInteger d = modInverse(e, phi);

        /*System.out.println("p = " + p + ", q = " + q);
        System.out.println("n = p × q = " + n);
        System.out.println("φ(n) = " + phi);
        System.out.println("e = " + e);*/
        System.out.println("d = " + d);

        //ASCII Conversion
        List<BigInteger> plaintext = stringToAscii(message);

        for (BigInteger ch : plaintext) {
            if (ch.compareTo(n) >= 0) {
                System.out.println("Chosen primes n = " + n + " are too small for plaintext. Please choose larger primes");
                return;
            }
        }

        /*System.out.println("Message converted to ASCII values:");
        System.out.println(plaintext);*/

        //Plaintext encryption
        List<BigInteger> ciphertext = encrypt(plaintext, e, n);
        /*System.out.println("Encrypted ciphertext:");
        System.out.println(ciphertext);*/

        //Save to file
        String filename = "rsa.txt";
        saveToFile(filename, n, e, ciphertext);

        //Read from file
        Object[] data = readFromFile(filename);
        BigInteger fileN = (BigInteger) data[0];
        BigInteger fileE = (BigInteger) data[1];
        List<BigInteger> fileCiphertext = (List<BigInteger>) data[2];

        //Decrypted p, q, phi and d
        BigInteger[] factors = factorN(fileN);
        if (factors == null) {
            System.out.println("Factor n not possible.");
            return;
        }

        BigInteger factoredP = factors[0];
        BigInteger factoredQ = factors[1];
        BigInteger phiRecovered = (factoredP.subtract(BigInteger.ONE)).multiply(factoredQ.subtract(BigInteger.ONE));
        BigInteger recoveredD = modInverse(fileE, phiRecovered);

        /*System.out.println("Recovered p = " + factoredP + ", q = " + factoredQ);
        System.out.println("Recovered φ(n) = " + phiRecovered);
        System.out.println("Recovered d = " + recoveredD);*/

        //Decryption
        List<BigInteger> decryptedAscii = decrypt(fileCiphertext, recoveredD, fileN);
        String decryptedMessage = asciiToString(decryptedAscii);

        System.out.println("Decrypted Message:");
        System.out.println(decryptedMessage);
    }
}