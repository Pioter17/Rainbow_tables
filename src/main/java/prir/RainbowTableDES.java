package prir;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Map;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.Random;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class RainbowTableDES {

    private static final String ALGORITHM = "DES";
    private static final int TABLE_SIZE = 2000; // Increased size for better coverage
    private static final int CHAIN_LENGTH = 10000; // Increased chain length
    private static final int THREAD_COUNT = 4; // Increased number of threads
    private final ConcurrentHashMap<String, String> rainbowTable = new ConcurrentHashMap<>();
    private final Random random = new Random();
    private static final SecretKey key;

    static {
        try {
            key = generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) throws Exception {
        RainbowTableDES rainbowTableDES = new RainbowTableDES();
        long startTime = System.currentTimeMillis();
        rainbowTableDES.generateRainbowTable("rainbow_table.txt", "generated_passwords.txt");
        long endTime = System.currentTimeMillis();
        System.out.println("Time taken: " + (endTime - startTime) + " ms");

        // Example of usage
        String plainText = "abceh";
        String cipherText = rainbowTableDES.encrypt(plainText);

        startTime = System.currentTimeMillis();
        String decryptedText = rainbowTableDES.lookup(cipherText);
        endTime = System.currentTimeMillis();
        System.out.println("Time taken: " + (endTime - startTime) + " ms");

        System.out.println("CipherText: " + cipherText);
        if (decryptedText == null) {
            System.out.println("Nie znaleziono hasła!");
        } else {
            System.out.println("Decrypted Text: " + decryptedText);
        }
    }

    public void generateRainbowTable(String rainbowTableFile, String passwordsFile) throws Exception {

        HashSet<String> set = new HashSet<>();
        do {
            String startPlainText = generateRandomPassword();
            set.add(startPlainText);
        } while (set.size() != TABLE_SIZE);
        System.out.println("Wyszedłem z while");

        List<String> firstColumn = set.stream().toList();

        ExecutorService executor = Executors.newFixedThreadPool(THREAD_COUNT);

        try (BufferedWriter rainbowWriter = new BufferedWriter(new FileWriter(rainbowTableFile));
             BufferedWriter passwordWriter = new BufferedWriter(new FileWriter(passwordsFile))) {

            for (int i = 0; i < TABLE_SIZE; i++) {
                int finalI = i;
                executor.submit(() -> {
                    try {
                        String startPlainText = firstColumn.get(finalI);
                        String endPlainText = startPlainText;
                        String cipherText = null;
                        StringBuilder chain = new StringBuilder(startPlainText);

                        for (int j = 0; j < CHAIN_LENGTH; j++) {
                            cipherText = encrypt(endPlainText);
                            chain.append(" -> ").append(cipherText);
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
                        rainbowTable.put(startPlainText, endPlainText);
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
        int length = 5; // length of the password
        String characters = "abcdefghijklmnoprstuvwxyz";
        StringBuilder password = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            password.append(characters.charAt(random.nextInt(characters.length())));
        }
        return password.toString();
    }

    public String encrypt(String plainText) throws Exception {

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
        for (int i = CHAIN_LENGTH - 1; i >= 0; i--) {
            final String[] currentText = {cipherText, "", "", ""};
            for (int j = i; j < CHAIN_LENGTH; j++) {
                currentText[0] = reduce(currentText[0], j);
                if (j == CHAIN_LENGTH - 1 && rainbowTable.containsValue(currentText[0])) {
                    int finalI = i;
                    rainbowTable.forEach((k, v) -> {
                        if (rainbowTable.get(k).equals(v)) {
                            currentText[0] = k;
                            for (int z = 0; z < finalI; z++) {
                                try {
                                    currentText[0] = encrypt(currentText[0]);
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }
//                                System.out.println("hash before " + currentText[0]);
                                currentText[0] = reduce(currentText[0], z);
                                try {
                                    currentText[1] = encrypt(currentText[0]);
                                } catch (Exception e) {
                                    throw new RuntimeException(e);
                                }
                                currentText[2] = reduce(currentText[1], z+1);
                                currentText[3] = reduce(cipherText, z+1);
                            }
                        }
                    });
                    String result = currentText[0];
//                    System.out.println("tekst wynik: " + result + ", hash wyniku: " + currentText[1] + ", redukcja hasha wyniku: " + currentText[2] + ", redukcja hasha hasła: " + currentText[3]);
                    return result;
//                    return rainbowTable.get(currentText);
                }
                try {
                    currentText[0] = encrypt(currentText[0]);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        return null;
    }

    private static SecretKey generateKey() throws NoSuchAlgorithmException {
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
