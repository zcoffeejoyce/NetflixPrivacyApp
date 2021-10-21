package org.zcj;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;

public class ClientScannerThread implements Runnable {
    private final ClientScanner cs;
    private final String clientURL;
    private final Integer clientID;
    private final ConcurrentHashMap<Integer, String> secretKeeper;

    /**
     * Create a thread that can use a ClientScanner to run an attack on a given clientURL.
     */
    public ClientScannerThread(ClientScanner cs, String clientURL, ConcurrentHashMap<Integer, String> secretKeeper) {
        this.cs = cs;
        this.clientURL = clientURL;
        this.clientID = Integer.valueOf(this.clientURL.substring(this.clientURL.lastIndexOf("/") + 1));
        this.secretKeeper = secretKeeper;
    }

    public ClientScanner getClientScanner() {
        return cs;
    }

    /**
     * Run the attack using the ClientScanner and store any secrets that were found.
     */
    @Override
    public void run() {
        String secretMessage = null;
        try {
            secretMessage = cs.attackClient(this.clientURL);
            if (this.clientID % 500 == 0) {
                System.out.print("%"); //Let user know we are still running...
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (secretMessage != null && !secretMessage.isEmpty()) {
            // Found some secretMessage - Store it in the centralized HashMap
            synchronized (secretKeeper) {
                this.secretKeeper.put(this.clientID, secretMessage);
            }
        }

    }
}
