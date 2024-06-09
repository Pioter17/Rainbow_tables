package prir;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

public class LookupThread extends Thread {
    private final List<String> keys;
    private final String lookupText;
    private String result;
    private final ConcurrentHashMap<String, String> rainbowTable;

    public LookupThread(List<String> keys, String lookupText, ConcurrentHashMap<String, String> rainbowTable) {
        this.keys = keys;
        this.lookupText = lookupText;
        this.rainbowTable = rainbowTable;
    }

    @Override
    public void run() {
        for (String key : keys) {
//            System.out.println("Jestem wątkiem nr: " + Thread.currentThread().threadId() + ", szukam tekstu: " + lookupText + ", przejrzalem wlasnie: " + rainbowTable.get(key));
//            System.out.println(rainbowTable.get(key).getClass());
            if (rainbowTable.get(key).equals(lookupText)) {
//                System.out.println("wniosek: równe, WĄTEK NUMER: " + Thread.currentThread().threadId() + " ZWRACA RESULT = " + key);
                result = key;
                break;
            }
        }
    }

    public String getResult() {
        return result;
    }
}