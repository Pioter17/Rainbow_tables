package prir;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.Random;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class RainbowTableDES {

    //  argumenty
    /*  1.
            g - generate (generuje hasła najpierw i zapisuje do pliku
            s - skip (nie generuje)
        2.
            hasło plain tekst
        3.
            wszystkie hasła
        4.
            liczba wątków
    */

    private static final String ALGORITHM = "DES";
    private static int TABLE_SIZE = 2000; // Increased size for better coverage
    private static int CHAIN_LENGTH = 10000; // Increased chain length
    private static int THREAD_COUNT = 4; // Number of threads to use
    private final ConcurrentHashMap<String, String> rainbowTable = new ConcurrentHashMap<>();
    private static final SecretKey key;
    private static final RandomPasswordGenerator passwordGenerator = new RandomPasswordGenerator();
    private static int passwordLength = 5;
    private static String PLAINTEXT = "abceh";

    static {
        try {
            key = generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 1) {
            passwordLength = args[1].length();
            TABLE_SIZE = Integer.parseInt(args[3]);
            CHAIN_LENGTH = Integer.parseInt(args[2]) / TABLE_SIZE;
            THREAD_COUNT = Integer.parseInt(args[3]);
            PLAINTEXT = args[1];
            if (args[0].equals("g")) {
                passwordGenerator.generateRandomPasswordList(passwordLength, TABLE_SIZE, "generated_passwords.txt", THREAD_COUNT);
            }
        }

        RainbowTableDES rainbowTableDES = new RainbowTableDES();
        long startTime = System.currentTimeMillis();
        rainbowTableDES.generateRainbowTable("rainbow_table.txt", "generated_passwords.txt");
        long endTime = System.currentTimeMillis();
        System.out.println("Time taken: " + (endTime - startTime) + " ms");

        String cipherText = rainbowTableDES.encrypt(PLAINTEXT);

        startTime = System.currentTimeMillis();
        String decryptedText = rainbowTableDES.lookup(cipherText);
        endTime = System.currentTimeMillis();
        System.out.println("Time taken: " + (endTime - startTime) + " ms");

        System.out.println("Plaintext: " + PLAINTEXT);
        System.out.println("CipherText: " + cipherText);
        System.out.println("Key: " + bytesToHex(key.getEncoded()));
        if (decryptedText == null) {
            System.out.println("Nie znaleziono hasła!");
        } else {
            System.out.println("Decrypted Text: " + decryptedText);
        }
    }

    public void generateRainbowTable(String rainbowTableFile, String passwordsFile) {
        class GenerateThread extends Thread {
            private final int start;
            private final BufferedWriter rainbowWriter;
            private final List<String> firstColumn;

            public GenerateThread(int start, List<String> firstColumn, BufferedWriter rainbowWriter) {
                this.start = start;
                this.firstColumn = firstColumn;
                this.rainbowWriter = rainbowWriter;
            }

            @Override
            public void run() {
                int finalI = start;
                try {
                    String startPlainText = firstColumn.get(finalI);
                    String endPlainText = startPlainText;
                    String cipherText = null;

                    for (int j = 0; j < CHAIN_LENGTH; j++) {
                        cipherText = encrypt(endPlainText);
                        endPlainText = reduce(cipherText, j);
                    }
                    synchronized (rainbowWriter) {
                        rainbowWriter.write(startPlainText + " -> ... -> " + endPlainText + "\n");
                    }
                    rainbowTable.put(startPlainText, endPlainText);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        try (BufferedWriter rainbowWriter = new BufferedWriter(new FileWriter(rainbowTableFile));
             BufferedReader passwordReader = new BufferedReader(new FileReader(passwordsFile))) {

            List<String> firstColumn = new ArrayList<>();
            String line;
            while ((line = passwordReader.readLine()) != null) {
                firstColumn.add(line);
            }

            GenerateThread[] threads = new GenerateThread[THREAD_COUNT];

            for (int i = 0; i < THREAD_COUNT; i++) {
                int start = i;
                threads[i] = new GenerateThread(start, firstColumn, rainbowWriter);
                threads[i].start();
            }

            for (GenerateThread thread : threads) {
                try {
                    thread.join();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String encrypt(String plainText) throws Exception {

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return bytesToHex(encrypted);
    }

    private String reduce(String cipherText, int round) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest((cipherText + round).getBytes());

            StringBuilder reduced = new StringBuilder();
            String characters = "abcdefghijklmnoprstuvwxyz";
            for (int i = 0; i < passwordLength; i++) {
                int charIndex = (hashBytes[i] & 0xFF) % characters.length();
                reduced.append(characters.charAt(charIndex));
            }

            return reduced.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public String lookup(String cipherText) {
        class LookupThread extends Thread {
            private final List<String> keys;
            private String result = null;

            public LookupThread(List<String> keys) {
                this.keys = keys;
            }

            public String getResult() {
                return result;
            }

            @Override
            public void run() {
                for (String key : keys) {
                    int i = CHAIN_LENGTH - 1;
                    String currentText = cipherText;
                    do {
                        currentText = reduce(currentText, i);
                        if (rainbowTable.containsValue(currentText)) {
                            int finalI = i;
                            if (rainbowTable.get(key).equals(currentText)) {
                                currentText = key;
                                for (int z = 0; z < finalI; z++) {
                                    try {
                                        currentText = encrypt(currentText);
                                    } catch (Exception e) {
                                        e.printStackTrace();
                                    }
                                    currentText = reduce(currentText, z);
                                }
                                result = currentText;
                                return;
                            }
                        }
                        try {
                            currentText = encrypt(currentText);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        i--;
                    } while (i >= 0);
                }
            }
        }

        List<String> keys = new ArrayList<>(rainbowTable.keySet());
        int chunkSize = (int) Math.ceil((double) keys.size() / THREAD_COUNT);
        LookupThread[] threads = new LookupThread[THREAD_COUNT];

        for (int i = 0; i < THREAD_COUNT; i++) {
            int start = i * chunkSize;
            int end = Math.min(start + chunkSize, keys.size());
            threads[i] = new LookupThread(keys.subList(start, end));
            threads[i].start();
        }

        for (LookupThread thread : threads) {
            try {
                thread.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        for (LookupThread thread : threads) {
            if (thread.getResult() != null) {
                return thread.getResult();
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
