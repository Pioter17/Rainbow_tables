package prir;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class RainbowTableDES {

    //  argumenty
    /*  1.
            g - generate (generuje hasła najpierw i zapisuje do pliku
            s - skip (nie generuje - czyta z pliku passwords.txt)
        2.
            haslo do znalezienia (plain text)
        3.
            liczba wierszy
        4.
            liczba kolumn
        5.
            liczba wątków
    */

    private static final String ALGORITHM = "DES";
    public static int TABLE_SIZE = 2000;
    public static int CHAIN_LENGTH = 10000;
    private static int THREAD_COUNT = 4; // Number of threads to use
    private static String PLAINTEXT = "abceh";
    private final ConcurrentHashMap<String, String> rainbowTable = new ConcurrentHashMap<>();
    private static final SecretKey key;
    private static final RandomPasswordGenerator passwordGenerator = new RandomPasswordGenerator();
    public static int passwordLength = 5;
    public static String ALPHABET = "password";

    static {
        try {
            key = generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 1) {
            PLAINTEXT = args[1];
            passwordLength = args[1].length();
            TABLE_SIZE = Integer.parseInt(args[2]);
            CHAIN_LENGTH = Integer.parseInt(args[3]);
            THREAD_COUNT = Integer.parseInt(args[4]);
            if (args[0].equals("g")) {
                passwordGenerator.generateRandomPasswordList(passwordLength, TABLE_SIZE, "passwords.txt", THREAD_COUNT);
            }
        }
        System.out.println("Łamanie haseł używając tablic tęczowych");
        System.out.println("Tablica dla hasel " + passwordLength + " znakowych");
        System.out.println("Dozwolony alfabet to " + ALPHABET);

        RainbowTableDES rainbowTableDES = new RainbowTableDES();
        long startTime = System.currentTimeMillis();
        rainbowTableDES.generateRainbowTable("rainbow_table.txt", "passwords.txt");
        long endTime = System.currentTimeMillis();
        System.out.println("Czas generowania tablicy: " + (endTime - startTime) + " ms");

        // Example of usage
//        String plainText = "abbaac";
//        System.out.println("zahashowany plain text(cipher text): " + encrypt(plainText));
        String cipherText = encrypt(PLAINTEXT);

        startTime = System.currentTimeMillis();
        String decryptedText = rainbowTableDES.lookup(cipherText);
        endTime = System.currentTimeMillis();
        System.out.println("Czas przeszukiwania tablicy: " + (endTime - startTime) + " ms");

        if (decryptedText == null) {
            System.out.println("Nie znaleziono hasła!");
        } else {
            System.out.println("Haslo zostalo znalezione!");
            System.out.println("Znalezione hasło: " + decryptedText);
        }
    }

    public void generateRainbowTable(String rainbowTableFile, String passwordsFile) {
        try (BufferedWriter rainbowWriter = new BufferedWriter(new FileWriter(rainbowTableFile));
             BufferedReader passwordReader = new BufferedReader(new FileReader(passwordsFile))) {

            List<String> firstColumn = new ArrayList<>();
            String line;
            while ((line = passwordReader.readLine()) != null) {
                firstColumn.add(line);
            }

            int chunkSize = (int) Math.ceil((double) TABLE_SIZE / THREAD_COUNT);
            GenerateThread[] threads = new GenerateThread[THREAD_COUNT];

            for (int i = 0; i < THREAD_COUNT; i++) {
                int start = i * chunkSize;
                int end = Math.min(start + chunkSize, TABLE_SIZE);
                threads[i] = new GenerateThread(start, end, firstColumn, rainbowWriter, rainbowTable);
                threads[i].start();
            }

            for (GenerateThread thread : threads) {
                try {
                    thread.join();
                } catch (InterruptedException e) {
                    System.err.println("Wystąpił błąd podczas joinowania wątków!");
                    e.printStackTrace();
                }
            }
        } catch (IOException e) {
            System.err.println("Wystąpił błąd z dostępem do pliku!");
            e.printStackTrace();
        }
    }


    public static String encrypt(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return bytesToHex(encrypted);
    }

    public static String reduce(String cipherText, int round) {
        int length = passwordLength;
        int alphabetLength = ALPHABET.length();
        StringBuilder reduced = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            int charIndex = (cipherText.charAt(i % cipherText.length()) + round) % alphabetLength;
            reduced.append(ALPHABET.charAt(charIndex));
        }
        return reduced.toString();
    }

    public String lookup(String cipherText) throws Exception {
        List<String> keys = new ArrayList<>(rainbowTable.keySet());
        int chunkSize = (int) Math.ceil((double) keys.size() / THREAD_COUNT);
        String lookupText;

        for(int i = CHAIN_LENGTH - 1; i >= 0; i--) {
            lookupText = cipherText;
            for(int j = i + 1; j < CHAIN_LENGTH; j++) {
                lookupText = reduce(lookupText, j - 1);
                lookupText = encrypt(lookupText);
            }
            lookupText = reduce(lookupText, CHAIN_LENGTH - 1);

            LookupThread[] threads = new LookupThread[THREAD_COUNT];
            for (int c = 0; c < THREAD_COUNT; c++) {
                int start = c * chunkSize;
                int end = Math.min(start + chunkSize, keys.size());
                threads[c] = new LookupThread(keys.subList(start, end), lookupText, rainbowTable);
                threads[c].start();
            }

            for (LookupThread thread : threads) {
                try {
//                    System.out.println("Joinuje watek: " + thread.threadId());
                    thread.join();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            for (LookupThread thread : threads) {
//                System.out.println("Sprawdzam result od threadu: " + thread.threadId());
                if (thread.getResult() != null) {
//                    System.out.println("Sprawdzam result od threadu: " + thread.threadId() + "I ZNALAZLEM " + thread.getResult());
                    String threadResult = thread.getResult();
//                    System.out.println("Znalazlem result: " + threadResult);

                    String[] currentText = new String[2];
                    currentText[0] = threadResult;
                    currentText[1] = encrypt(threadResult);

                    for(int k = 0; k < CHAIN_LENGTH; k++) {
                        if(currentText[1].equals(cipherText)) {
                            return currentText[0];
                        }
                        currentText[0] = reduce(currentText[1], k);
                        currentText[1] = encrypt(currentText[0]);
                    }
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
