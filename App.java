package demo;

// INTENTIONALLY VULNERABLE demo for GitHub code scanning (CodeQL). Never deploy.

import com.sun.net.httpserver.HttpServer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Random;

public class App {
    private static final Logger log = LogManager.getLogger(App.class);

    // Hardcoded credentials (java/hardcoded-credential-api-call)
    private static final String DB_PASSWORD = "admin123";
    private static final String AES_KEY = "0123456789abcdef";

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);

        // 1. SQL injection (java/sql-injection)
        server.createContext("/user", ex -> {
            String name = param(ex.getRequestURI(), "name");
            String out = "";
            try (Connection c = DriverManager.getConnection("jdbc:h2:mem:demo", "sa", DB_PASSWORD);
                 Statement st = c.createStatement()) {
                ResultSet rs = st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
                while (rs.next()) out += rs.getString(1) + "\n";
            } catch (Exception e) { out = e.toString(); }
            reply(ex, out);
        });

        // 2. Command injection (java/command-line-injection)
        server.createContext("/ping", ex -> {
            String host = param(ex.getRequestURI(), "host");
            Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", "ping -c 1 " + host});
            reply(ex, new String(p.getInputStream().readAllBytes()));
        });

        // 3. Reflected XSS (java/xss)
        server.createContext("/hello", ex ->
            reply(ex, "<h1>Hello " + param(ex.getRequestURI(), "name") + "</h1>"));

        // 4. Path traversal (java/path-injection)
        server.createContext("/read", ex -> {
            String file = param(ex.getRequestURI(), "file");
            reply(ex, new String(Files.readAllBytes(Paths.get("/var/data/" + file))));
        });

        // 5. Unsafe deserialization (java/unsafe-deserialization)
        server.createContext("/load", ex -> {
            try (ObjectInputStream in = new ObjectInputStream(ex.getRequestBody())) {
                reply(ex, String.valueOf(in.readObject()));
            } catch (Exception e) { reply(ex, e.toString()); }
        });

        // 6. XXE (java/xxe)
        server.createContext("/xml", ex -> {
            try {
                DocumentBuilderFactory f = DocumentBuilderFactory.newInstance(); // no secure processing
                Document d = f.newDocumentBuilder().parse(new InputSource(ex.getRequestBody()));
                reply(ex, d.getDocumentElement().getTextContent());
            } catch (Exception e) { reply(ex, e.toString()); }
        });

        // 7. Log injection + Log4Shell-vulnerable log4j-core 2.14.1 (java/log-injection)
        server.createContext("/log", ex -> {
            log.error("Bad input: " + param(ex.getRequestURI(), "msg"));
            reply(ex, "logged");
        });

        // 8. Weak crypto: MD5 hash, ECB mode, hardcoded key (java/weak-cryptographic-algorithm)
        server.createContext("/hash", ex -> {
            try {
                byte[] h = MessageDigest.getInstance("MD5")
                        .digest(param(ex.getRequestURI(), "pw").getBytes(StandardCharsets.UTF_8));
                Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
                c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(AES_KEY.getBytes(), "AES"));
                reply(ex, java.util.Base64.getEncoder().encodeToString(c.doFinal(h)));
            } catch (Exception e) { reply(ex, e.toString()); }
        });

        // 9. Insecure randomness for a session token (java/insecure-randomness)
        server.createContext("/token", ex ->
            reply(ex, Long.toHexString(new Random().nextLong())));

        server.start();
    }

    private static String param(URI uri, String key) {
        String q = uri.getQuery();
        if (q == null) return "";
        for (String kv : q.split("&")) {
            String[] p = kv.split("=", 2);
            if (p[0].equals(key) && p.length > 1) return java.net.URLDecoder.decode(p[1], StandardCharsets.UTF_8);
        }
        return "";
    }

    private static void reply(com.sun.net.httpserver.HttpExchange ex, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(200, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }
}
