/*
 * MicroMavenMiscellany v1
 *
 * Copyright (C) 2021 by CoolMineman
 *
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.io.Writer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Properties;
import java.util.concurrent.Executors;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Single class file maven server
 * 
 * References:
 * https://dzone.com/articles/simple-http-server-in-java
 */
public class MicroMavenMiscellany implements HttpHandler {
    static final Path DIR;
    static final Path FILES;
    static {
        try {
            // We are not in a jar
            DIR = Paths.get(MicroMavenMiscellany.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            FILES = DIR.resolve("files");
            Files.createDirectories(FILES);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    static final Path CONFIG = DIR.resolve("config.properties");
    static final boolean DEBUG = Boolean.getBoolean("debug");
    
    //Config
    int port;
    int threads;
    byte[] salt;
    byte[] hashedAuth;
    
    public static void main(String[] args) throws Exception {
        new MicroMavenMiscellany().main0(args);
    }
    
    void main0(String[] args) throws Exception {
        if (args.length == 1 && "run".equals(args[0])) {
            readConfig();
            HttpServer server = HttpServer.create(new InetSocketAddress("localhost", port), 0);
            server.createContext("/", this);
            if (threads > 1) {
                server.setExecutor(Executors.newFixedThreadPool(threads));
            }
            server.start();
        } else if (args.length == 1 && "config".equals(args[0])) {
            salt = new byte[256];
            new SecureRandom().nextBytes(salt);
            String auth = new String(System.console().readPassword("Enter authentication; {username}:{password} format: "));
            if (!new String(System.console().readPassword("Enter again to verify: ")).equals(auth)) {
                throw new RuntimeException("Authentication did not match");
            }
            // Just hash the entire auth string so we don't need to do parsing
            hashedAuth = hash("Basic " + Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.UTF_8)));
            port = Integer.parseInt(System.console().readLine("Enter port: "));
            threads = Integer.parseInt(System.console().readLine("Enter thread count; (Roughly how many people can use at once): "));
            writeConfig();
        } else {
            System.err.println("Usage:");
            System.err.println("mmm run");
            System.err.println("mmm config");
        }
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            switch (exchange.getRequestMethod()) {
                case "GET":
                    get(exchange);
                    break;
                case "PUT":
                    put(exchange);
                    break;
                default:
                    throw new IOException("unsupported http request");
            }
        } catch (Exception e) {
            if (DEBUG) e.printStackTrace();
            exchange.sendResponseHeaders(418, -1);
        }
    }
    
    void put(HttpExchange exchange) throws IOException {
        try {
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            // MessageDigest.isEqual avoids Timing attack
            if (auth != null && MessageDigest.isEqual(hash(auth), hashedAuth)) {
                try (InputStream i = new BufferedInputStream(exchange.getRequestBody())) {
                    Path target = FILES.resolve(exchange.getRequestURI().getPath().substring(1)).toFile().getCanonicalFile().toPath(); // Avoid .. to write elsewere on the fs
                    if (DEBUG) System.out.println("Uploading " + target);
                    if (!target.startsWith(FILES)) {
                        throw new UnsupportedOperationException("Illegal path");
                    }
                    Files.createDirectories(target.getParent());
                    Files.copy(i, target, StandardCopyOption.REPLACE_EXISTING);
                }
                exchange.sendResponseHeaders(201, -1);
            } else {
                exchange.sendResponseHeaders(403, -1);
            }
        } catch (Exception e) {
            throw new IOException(e);
        }
    }
    
    void get(HttpExchange exchange) throws IOException {
        Path target = FILES.resolve(exchange.getRequestURI().getPath().substring(1)).toFile().getCanonicalFile().toPath(); // Avoid .. to read elsewere on the fs
        System.err.println(target);
        if (!target.startsWith(FILES)) {
            throw new UnsupportedOperationException("Illegal path");
        }
        if (Files.isRegularFile(target)) {
            exchange.sendResponseHeaders(200, Files.size(target));
            try (OutputStream o = exchange.getResponseBody()) {
                Files.copy(target, o);
            }
        } else {
            exchange.sendResponseHeaders(404, -1);
        }
    }

    byte[] hash(String s) throws Exception {
        // PBKDF2 is used because it is in the standard library for Java 8+
        // Recommended 120,000 iterations for SHA512 https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
        KeySpec spec = new PBEKeySpec(s.toCharArray(), salt, 120000, 512);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        return f.generateSecret(spec).getEncoded();
    }
    
    void writeConfig() throws IOException {
        Properties o = new Properties();
        o.setProperty("port", Integer.toString(port));
        o.setProperty("threads", Integer.toString(threads));
        o.setProperty("salt", Base64.getEncoder().encodeToString(salt));
        o.setProperty("hashedAuth", Base64.getEncoder().encodeToString(hashedAuth));
        try (Writer w = Files.newBufferedWriter(CONFIG)) {
            o.store(w, null);
        }
    }
    
    void readConfig() throws IOException {
        Properties o = new Properties();
        try (Reader r = Files.newBufferedReader(CONFIG)) {
            o.load(r);
        }
        port = Integer.parseInt(o.getProperty("port"));
        threads = Integer.parseInt(o.getProperty("threads"));
        salt = Base64.getDecoder().decode(o.getProperty("salt"));
        hashedAuth = Base64.getDecoder().decode(o.getProperty("hashedAuth"));
    }
}