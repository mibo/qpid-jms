package org.apache.qpid.jms.transports.oauth;

import org.apache.qpid.jms.transports.TransportOptions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * OAuth token request handler.
 */
public class OAuthHandler {
    private static final Logger LOG = LoggerFactory.getLogger(OAuthHandler.class);

    //  https://tools.ietf.org/html/rfc6749#section-4.3
    @SuppressWarnings("squid:S2068") private static final String OAUTH_PASSWORD_FLOW_BODY_TEMPLATE =
        "username=%s&password=%s&grant_type=password&response_type=token"; // NOSONAR - no password only a template
    // https://tools.ietf.org/html/rfc6749#section-4.4
    private static final String OAUTH_CLIENT_FLOW_BODY_TEMPLATE =
        "client_id=%s&client_secret=%s&grant_type=client_credentials&response_type=token";

    public static final String CLIENT_CREDENTIALS_GRANT = "client_credentials";
    public static final String PASSWORD_GRANT = "password"; // NOSONAR - no password only a key
    public static final String AUTH_BEARER = "Bearer ";
    public static final String ACCEPT_HEADER = "Accept";
    public static final String CONTENT_TYPE_HEADER = "Content-Type";
    public static final String APPLICATION_X_WWW_FORM_URLENCODED = "application/x-www-form-urlencoded";
    public static final String APPLICATION_JSON = "application/json";
    public static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String HTTP_METHOD_POST = "POST";
    private static final String AUTH_BASIC = "Basic ";

    private static final int BUFFER_SIZE = 1024 * 64;
    private static final int MAX_READ_SIZE = 1024 * 64 * 10;

    private final TransportOptions transportOptions;

    public OAuthHandler(TransportOptions options) {
        this.transportOptions = options;
    }

    /**
     * Do the token request based on given parameters (via ctor).
     *
     * @return the extracted JWT token (including the AUTH_BEARER prefix).
     * @throws IOException if something goes wrong.
     */
    public String doTokenRequest() throws IOException {
        String oauthFlow = transportOptions.getOAuthGrantType();
        if (PASSWORD_GRANT.equalsIgnoreCase(oauthFlow)) {
            String url = transportOptions.getOAuthTokenEndpoint();
            String user = transportOptions.getOAuthUser();
            String password = transportOptions.getOAuthPassword();
            return AUTH_BEARER + doTokenRequestPasswordFlow(url, user, password);
        } else if (CLIENT_CREDENTIALS_GRANT.equalsIgnoreCase(oauthFlow)) {
            String url = transportOptions.getOAuthTokenEndpoint();
            String clientId = transportOptions.getOAuthClientId();
            String clientSecret = transportOptions.getOAuthClientSecret();
            return AUTH_BEARER + doTokenRequestClientFlow(url, clientId, clientSecret);
        }
        throw new IllegalStateException("Found unknown grant type (value: " + oauthFlow + ")");
    }

    //
    // below all HTTP related stuff
    //

    /**
     * https://tools.ietf.org/html/rfc6749#section-4.3
     */
    private String doTokenRequestPasswordFlow(String url, String user, String password) throws IOException {
        LOG.trace("Start doTokenRequestPasswordFlow:: {}", url);
        String body = String.format(OAUTH_PASSWORD_FLOW_BODY_TEMPLATE, user, password);
        return doTokenRequestWithBody(url, body);
    }

    /**
     * https://tools.ietf.org/html/rfc6749#section-4.4
     *
     * URL (method POST): <base URL>?grant_type=client_credentials
     * Required HTTP Header: "Authorization: Basic <clientid and clientsecret in base64>"
     */
    private String doTokenRequestClientFlow(String url, String clientId, String clientSecret) throws IOException {
        LOG.trace("Start doTokenRequestClientFlow:: {}", url);
        String body = String.format(OAUTH_CLIENT_FLOW_BODY_TEMPLATE, clientId, clientSecret);

        Map<String, String> headers = new HashMap<>();
        headers.put(CONTENT_TYPE_HEADER, APPLICATION_X_WWW_FORM_URLENCODED);
        headers.put(ACCEPT_HEADER, APPLICATION_JSON);

        String cid = clientId + ":" + clientSecret;
        String b64 = Base64.getEncoder().encodeToString(cid.getBytes(StandardCharsets.ISO_8859_1));
        headers.put(OAuthHandler.AUTHORIZATION_HEADER, AUTH_BASIC + b64);

        final String postUrl = url + "?grant_type=client_credentials";
        String response = post(postUrl, body, headers);
        return extractToken(response);
    }

    // see -> #doTokenRequestPasswordFlow(...)
    private String doTokenRequestWithBody(String url, String body) throws IOException {
        Map<String, String> headers = new HashMap<>();
        headers.put(CONTENT_TYPE_HEADER, APPLICATION_X_WWW_FORM_URLENCODED);
        headers.put(ACCEPT_HEADER, APPLICATION_JSON);

        String response = post(url, body, headers);
        return extractToken(response);
    }

    /**
     * https://tools.ietf.org/html/rfc6749#section-4.3.3 {
     * "access_token":"2YotnFZFEjr1zCsicMWpAA", "token_type":"example",
     * "expires_in":3600, "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
     * "example_parameter":"example_value" }
     *
     * @param response http response from which the token gets extracted
     * @return the extracted token
     */
    private String extractToken(String response) throws IOException {
        int index = response.indexOf("\"access_token\"");
        int tokenIndex = response.indexOf("\"", index + 14) + 1;
        int lastTokenIndex = response.indexOf("\"", tokenIndex);
        if (index <= 0 || lastTokenIndex <= tokenIndex) {
            throw new IOException("Unable to extract access_token from response: " + response);
        }
        return response.substring(tokenIndex, lastTokenIndex);
    }

    private String post(String url, String content, Map<String, String> additionalHeaders) throws IOException {
        HttpURLConnection con = openConnection(url);
        con.setRequestMethod(HTTP_METHOD_POST);

        additionalHeaders.forEach(con::setRequestProperty);

        con.setDoOutput(true);
        try (OutputStream os = con.getOutputStream(); WritableByteChannel outChannel = Channels.newChannel(os)) {
            ByteBuffer outBuffer = ByteBuffer.wrap(content.getBytes(StandardCharsets.UTF_8));
            int wrote = outChannel.write(outBuffer);
            if (wrote < 0) {
                throw new IOException("No data written");
            }

            return handleResponse(con);
        }
    }

    private HttpURLConnection openConnection(String url) throws IOException {
        URL urly = new URL(url);
        //    Proxy proxy = new Proxy();
        // TODO: enable proxy if necessary
        HttpURLConnection con = (HttpURLConnection) urly.openConnection();
        if (con instanceof HttpsURLConnection) {
            LOG.trace("Configure HTTPS connection.");
            // TODO: enable ssl stuff if necessary
            // currently allow each hostname (NO VERIFICATION)
            // hostname,session -> h,s
            ((HttpsURLConnection) con).setHostnameVerifier((h, s) -> Boolean.TRUE);
        }
        return con;
    }

    private String handleResponse(HttpURLConnection con) throws IOException {
        int responseCode = con.getResponseCode();
        if (!is2xx(responseCode)) {
            String message = String.format("Got a none 2xx response code '%s'.", responseCode);
            if (LOG.isTraceEnabled()) {
                LOG.trace(message + " Used token endpoint: " + con.getURL());
            } else {
                LOG.warn(message);
            }
            throw new IOException(message);
        }

        return readResponseBody(con);
    }

    private String readResponseBody(HttpURLConnection con) throws IOException {
        Charset responseCharset = getCharset(con);
        try (InputStream is = con.getInputStream(); ReadableByteChannel inChannel = Channels.newChannel(is)) {

            ByteBuffer inBuffer = ByteBuffer.allocate(BUFFER_SIZE);
            byte[] tmp = new byte[BUFFER_SIZE];
            StringBuilder response = new StringBuilder();
            int maxRead = MAX_READ_SIZE;
            int read = inChannel.read(inBuffer);
            while (read > 0 && maxRead > 0) {
                maxRead -= read;
                inBuffer.flip();
                inBuffer.get(tmp, 0, read);
                response.append(new String(tmp, 0, read, responseCharset));
                inBuffer.clear();
                read = inChannel.read(inBuffer);
            }
            if (maxRead <= 0) {
                throw new IOException("Buffer overflow for response.");
            }
            return response.toString();
        }
    }

    private Charset getCharset(HttpURLConnection connection) {
        // TODO: fix this
        String contentTypeHeader = connection.getHeaderField(CONTENT_TYPE_HEADER);
        if (contentTypeHeader != null) {
            String contentTypeHeaderLc = contentTypeHeader.toLowerCase(Locale.US);
            if (contentTypeHeaderLc.contains("utf-8")) {
                return StandardCharsets.UTF_8;
            } else if (contentTypeHeaderLc.contains("iso-8859-1")) {
                return StandardCharsets.ISO_8859_1;
            }
        }
        return StandardCharsets.US_ASCII;
    }

    private boolean is2xx(int responseCode) {
        return responseCode >= 200 && responseCode < 300;
    }

}
