import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;

public class Zad1 {

    private static final String AES_CBC = "AES/CBC/PKCS5Padding";
    private static final String AES_CTR = "AES/CTR/PKCS5Padding";
    private static final String AES_GCM = "AES/GCM/NoPadding";

    public static void main(String[] args) {

        int option;
        String cipherMode;
        String input;
        KeyStore keyStore;
        Key key;

        if (args.length != 5) {
            System.err.println("ERROR: Wrong amount of arguments.\n"
                    + "Correct use: \n"
                    + "-<encrypt|enc|e|decrypt|dec|d> -<ctr|cbc|gcm> <input file path> <keystore path> <key alias>");
            return;
        }

        

        input = args[2];

        switch (args[0]) {
            case "-encrypt":
            case "-enc":
            case "-e":
                option = Cipher.ENCRYPT_MODE;
                break;
            case "-decrypt":
            case "-dec":
            case "-d":
                option = Cipher.DECRYPT_MODE;
                if (!input.endsWith(".aes256")) {
                    System.err.println("ERROR: wrong input file extension");
                    return;
                }
                break;
            default:
                System.err.println("ERROR: wrong first argument. \n"
			+ "Correct use: \n"
			+ "-<encrypt|enc|e|decrypt|dec|d> -<ctr|cbc|gcm> <input file path> <keystore path> <key alias>");
                return;
        }

        switch (args[1]) {
            case "-cbc":
                cipherMode = AES_CBC;
                break;
            case "-gcm":
                cipherMode = AES_GCM;
                break;
            case "-ctr":
                cipherMode = AES_CTR;
                break;
            default:
                System.err.println("ERROR: wrong second argument. \n"
			+ "Correct use: \n"
			+ "<encrypt|enc|e|decrypt|dec|d> -<ctr|cbc|gcm> <input file path> <keystore path> <key alias>");
                return;
        }

        try {
            
            keyStore = KeyStore.getInstance("JCEKS");
            FileInputStream keyStoreStream = new FileInputStream(new File(args[3]));
            keyStore.load(keyStoreStream, System.console().readPassword("Keystore password: "));
            key = keyStore.getKey(args[4], System.console().readPassword("Key password: "));

            cipher(option, cipherMode, input, key);
        } catch (KeyStoreException | UnrecoverableKeyException | CertificateException e) {
            System.err.println("Key Error: check keystore path or make sure password is correct");
            e.printStackTrace();
        } catch (InvalidKeyException| NoSuchAlgorithmException | InvalidAlgorithmParameterException
                | NoSuchPaddingException | BadPaddingException | NoSuchProviderException
                | IllegalBlockSizeException e) {
            System.err.println("Cipher Error: check if correct key was chosen");
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("File Access Error: check keystore or input file path");
            e.printStackTrace();
        }

    }

    private static void cipher(int cMode, String mode, String inputFile, Key key) throws NoSuchPaddingException,
            NoSuchAlgorithmException, IOException, InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {

        Security.addProvider(new BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance(mode, "BC");

        SecureRandom rand = new SecureRandom();

        byte[] ivBytes = new byte[16];
        byte[] inputBytes;

        if (cMode == Cipher.ENCRYPT_MODE) {

            rand.nextBytes(ivBytes);
            inputBytes = Files.readAllBytes(Paths.get(inputFile));

        } else {    

            byte[] fileBytes = Files.readAllBytes(Paths.get(inputFile));
            ivBytes = Arrays.copyOfRange(fileBytes, 0, 16);
            inputBytes = Arrays.copyOfRange(fileBytes, 16, fileBytes.length);

        }

        cipher.init(cMode, key, new IvParameterSpec(ivBytes));
        byte[] resultBytes = cipher.doFinal(inputBytes);

        if (cMode == Cipher.ENCRYPT_MODE) {

            Path output = Files.createFile(Paths.get(inputFile + ".aes256"));
            Files.write(output, ivBytes);
            Files.write(output, resultBytes, StandardOpenOption.WRITE, StandardOpenOption.APPEND);

            System.out.println("Encryption Successful! File saved to: " + output.toString());

        } else {    

            Path output = Files.createFile(Paths.get(inputFile.substring(0, inputFile.lastIndexOf(".aes256"))));
            Files.write(output, resultBytes);
            System.out.println("Decryption Successful, File saved to: " + output.toString());

        }
    }
}
