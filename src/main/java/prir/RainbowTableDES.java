package prir;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.Random;

public class RainbowTableDES {

    private static final String ALGORITHM = "DES";
    private static final int TABLE_SIZE = 6; // Increased size
    private static final int CHAIN_LENGTH = 10; // Length of the reduction chain
    private static final int THREAD_COUNT = 1;
    private final ConcurrentHashMap<String, String> rainbowTable = new ConcurrentHashMap<>();
    private final Random random = new Random();

    public static void main(String[] args) throws Exception {
        RainbowTableDES rainbowTableDES = new RainbowTableDES();
        long startTime = System.currentTimeMillis();
        rainbowTableDES.generateRainbowTable("rainbow_table.txt", "generated_passwords.txt");
        long endTime = System.currentTimeMillis();
        System.out.println("Time taken: " + (endTime - startTime) + " ms");

        // Example of usage
        String plainText = "ab";
        String cipherText = rainbowTableDES.encrypt(plainText);
        System.out.println("CipherText: " + cipherText);

        String decryptedText = rainbowTableDES.lookup(cipherText);
        System.out.println("Decrypted Text: " + decryptedText);
    }

    public void generateRainbowTable(String rainbowTableFile, String passwordsFile) throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(THREAD_COUNT);

        try (BufferedWriter rainbowWriter = new BufferedWriter(new FileWriter(rainbowTableFile));
             BufferedWriter passwordWriter = new BufferedWriter(new FileWriter(passwordsFile))) {

            for (int i = 0; i < TABLE_SIZE; i++) {
                executor.submit(() -> {
                    try {
                        String startPlainText = generateRandomPassword();
                        String endPlainText = startPlainText;
                        String cipherText = null;
                        StringBuilder chain = new StringBuilder(startPlainText);

                        for (int j = 0; j < CHAIN_LENGTH; j++) {
                            cipherText = encrypt(endPlainText);
                            endPlainText = reduce(cipherText, j);
                            chain.append(" -> ").append(endPlainText);
                            // Write each generated password to the file
                            synchronized (passwordWriter) {
                                passwordWriter.write(endPlainText + "\n");
                            }
                        }
                        synchronized (rainbowWriter) {
                            rainbowWriter.write(chain.toString() + "\n");
                        }
                        rainbowTable.put(endPlainText, startPlainText);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });
            }

            executor.shutdown();
            executor.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String generateRandomPassword() {
        int length = 2; // length of the password
        String characters = "abc";
        StringBuilder password = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            password.append(characters.charAt(random.nextInt(characters.length())));
        }
        return password.toString();
    }

    public String encrypt(String plainText) throws Exception {
        SecretKey key = generateKey();
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return bytesToHex(encrypted);
    }

    private String reduce(String cipherText, int round) {
        int length = 2; // length of the password
        StringBuilder reduced = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            int charIndex = (cipherText.charAt(i % cipherText.length()) + round) % 3;
            reduced.append("abc".charAt(charIndex));
        }
        return reduced.toString();
    }

    public String lookup(String cipherText) {
        return rainbowTable.get(cipherText);
    }

    private SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(new SecureRandom());
        return keyGenerator.generateKey();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
