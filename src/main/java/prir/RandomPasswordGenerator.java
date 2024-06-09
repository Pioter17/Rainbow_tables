package prir;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class RandomPasswordGenerator {
    private final Random random = new Random();

    public String generateRandomPassword(int len) {
        String characters = RainbowTableDES.ALPHABET;
        StringBuilder password = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            password.append(characters.charAt(random.nextInt(characters.length())));
        }
        return password.toString();
    }

    public void generateRandomPasswordList(int passwordLength, int TABLE_SIZE, String passwordsFile, int THREAD_COUNT) {
        HashSet<String> set = new HashSet<>();
        do {
            String startPlainText = generateRandomPassword(passwordLength);
            set.add(startPlainText);
        } while (set.size() != TABLE_SIZE);
//        System.out.println("Wyszedłem z while");
        List<String> firstColumn = set.stream().toList();
        ExecutorService executor = Executors.newFixedThreadPool(THREAD_COUNT);

        try (BufferedWriter passwordWriter = new BufferedWriter(new FileWriter(passwordsFile))) {
            for (int i = 0; i < TABLE_SIZE; i++) {
                int finalI = i;
                executor.submit(() -> {
                    try {
                        String startPlainText = firstColumn.get(finalI);
                        synchronized (passwordWriter) {
                            passwordWriter.write(startPlainText + "\n");
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });
            }
            executor.shutdown();
            executor.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}
