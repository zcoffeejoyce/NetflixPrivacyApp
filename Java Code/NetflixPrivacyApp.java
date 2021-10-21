package org.zcj;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.time.Instant;
import java.time.ZoneId;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

/**
 * This is my main entry point for the Privacy Assurance and Engineering automation exercise
 * Zachary Joyce (zcoffeejoyce@gmail.com)
 * Oct 20, 2021
 */
public class NetflixPrivacyApp {

    private static Instant startTime;
    private static Instant endTime;
    // Restraints given by exercise
    private static final String ALL_CLIENTS_URL = "http://appsec-exercise.test.netflix.net/instructions/clients.txt";
    private static final int MAX_CONNECTIONS = 10;

    /**
     * Main entry point for running my program. Calling main() will kick off the automation
     * process to scan all client accounts in ALL_CLIENTS_URL and attempt an injection attack
     * as part of a batch processing API call.
     * This function will spin up multiple threads as workers to complete the task, as well
     * as track the execution time of the program and print out any vulnerable clients it finds.
     */
    public static void main(String[] args) throws IOException {
        startTime = Instant.now();
        System.out.println("I solemnly swear I am up to no good...");

        // Create Map of client IDs to Secrets we find
        ConcurrentHashMap<Integer, String> clientsToSecrets = new ConcurrentHashMap<>();
        // Initialize Thread Pool to run up to 10 scanners at once
        ExecutorService executor = Executors.newFixedThreadPool(MAX_CONNECTIONS);
        Queue<ClientScanner> scanners = new LinkedList<>();
        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            scanners.add(new ClientScanner());
        }

        // Grab the input clients list to check
        HttpURLConnection connect = getConnection(ALL_CLIENTS_URL);
        BufferedReader br = new BufferedReader(new InputStreamReader(connect.getInputStream()));
        List<String> clientList = br.lines().collect(Collectors.toList());
        br.close();

        // Check all clients for vulnerabilities
        for (String clientURL : clientList) {
            // Assign thread to scan new clients as the threads become available
            ClientScannerThread worker = new ClientScannerThread(scanners.remove(), clientURL, clientsToSecrets);
            executor.execute(worker);
            // Release scanner as available
            scanners.add(worker.getClientScanner());
        }
        executor.shutdown();
        while (!executor.isTerminated()) {
        } //Do not proceed while threads are running

        // At this point, all calculations are done. Stop the clock.
        endTime = Instant.now();
        // Present the results
        printClientSecrets(clientsToSecrets);
        printElapsedTime();
        System.out.println("\n\nMischief Managed");
    }

    /**
     * Create an open HttpURLConnection from a URL String.
     * Helper function to make this process easier.
     */
    private static HttpURLConnection getConnection(String urlString) throws IOException {
        URL url = new URL(urlString);
        HttpURLConnection connect = (HttpURLConnection) url.openConnection();
        connect.setRequestMethod("GET");
        connect.setDoOutput(true);
        connect.setRequestProperty("Content-Type", "text/plain");

        return connect;
    }

    /**
     * Helper function to print output of clients/secrets to console
     */
    private static void printClientSecrets(ConcurrentHashMap<Integer, String> clientsToSecrets) {
        System.out.printf("%nThere are %d Vulnerable Clients!%n", clientsToSecrets.size());
        clientsToSecrets
                .entrySet()
                .stream()
                .sorted(Comparator.comparingInt(Map.Entry::getKey))
                .forEach(entry ->
                        System.out.printf("Client: %d\nSecret: %s%n___%n", entry.getKey(), entry.getValue()));
    }

    /**
     * Helper function to print out program performance.
     * - Start Time
     * - End Time
     * - Elapsed Time (in seconds)
     */
    private static void printElapsedTime() {
        System.out.println("System Performance:");
        long elapsed = endTime.getEpochSecond() - startTime.getEpochSecond();
        System.out.println("Start Time: " + startTime.atZone(ZoneId.systemDefault()));
        System.out.println("End Time: " + endTime.atZone(ZoneId.systemDefault()));
        System.out.println("Elapsed Seconds: " + elapsed);
    }
}
