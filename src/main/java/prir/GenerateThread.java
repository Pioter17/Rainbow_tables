package prir;

import java.io.BufferedWriter;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

public class GenerateThread extends Thread {
    private final int start;
    private final int end;
    private final BufferedWriter rainbowWriter;
    private final List<String> firstColumn;
    private final int CHAIN_LENGTH = RainbowTableDES.CHAIN_LENGTH;
    private final ConcurrentHashMap<String, String> rainbowTable;

    public GenerateThread(int start, int end, List<String> firstColumn, BufferedWriter rainbowWriter, ConcurrentHashMap<String, String> rainbowTable) {
        this.start = start;
        this.end = end;
        this.firstColumn = firstColumn;
        this.rainbowWriter = rainbowWriter;
        this.rainbowTable = rainbowTable;
    }

    @Override
    public void run() {
//        System.out.println("Moj start: " + start + " end: " + end);
        for (int i = start; i < end; i++) {
            try {
                String startPlainText = firstColumn.get(i);
//                System.out.println("Pobieram plaintext(" + i + "): " + startPlainText);
                String endPlainText = startPlainText;
                String cipherText = null;
//                int r = 1;

                for (int j = 0; j < CHAIN_LENGTH; j++) {
                    cipherText = RainbowTableDES.encrypt(endPlainText);
//                    System.out.println("Jestem w iteracji j = " + j + ", enkryptuję: " + endPlainText + ", wyszlo mi: " + cipherText);
                    endPlainText = RainbowTableDES.reduce(cipherText, j);
//                    System.out.println("Jestem w iteracji j = " + j + "Redukuję (po raz "+r+") " + cipherText + ", wychodzi mi: " + endPlainText);
//                    r++;
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
}
