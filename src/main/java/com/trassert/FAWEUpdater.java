package com.trassert;

import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.scheduler.BukkitRunnable;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.logging.Level;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class FAWEUpdater extends JavaPlugin {

    private static final String STATE_FILE_NAME = "state.properties";
    private static final Pattern BUILD_NUMBER_PATTERN = Pattern.compile("SNAPSHOT-(\\d+)");
    private static final Pattern JSON_BUILD_NUM_PATTERN = Pattern.compile("\"number\"\\s*:\\s*(\\d+)");

    @Override
    public void onEnable() {
        saveDefaultConfig();

        if (!getConfig().getBoolean("enabled", true)) {
            getLogger().info("FAWEUpdater выключен в конфиге.");
            return;
        }

        System.setProperty("jdk.http.auth.tunneling.disabledSchemes", "");
    }

    private void doUpdate() throws Exception {
        String baseUrl = getConfig().getString("jenkins.baseUrl", "https://ci.athion.net").trim();
        String jobPath = getConfig().getString("jenkins.jobPath", "/job/FastAsyncWorldEdit").trim();
        String buildRef = getConfig().getString("jenkins.build", "lastSuccessfulBuild").trim();

        String apiUrl = String.format("%s%s/%s/api/json?tree=number,artifacts[fileName,relativePath]",
                baseUrl.replaceAll("/$", ""), jobPath, buildRef);

        getLogger().info("Проверка обновлений: " + apiUrl);

        String json = HttpClient.fetchString(this, apiUrl);

        long remoteBuildNumber = parseBuildNumberFromJson(json);
        if (remoteBuildNumber == -1) {
            getLogger().warning("Не удалось распарсить номер билда из ответа Jenkins.");
            return;
        }

        long installedBuild = getInstalledFaweBuildNumber();
        if (installedBuild >= remoteBuildNumber) {
            getLogger().info("FAWE актуален (installed: " + installedBuild + " >= remote: " + remoteBuildNumber + ").");
            updateState(remoteBuildNumber, "unknown");
            return;
        }

        getLogger().info("Найдена новая версия: " + remoteBuildNumber + " (Текущая: " + installedBuild + ")");

        String prefix = getConfig().getString("artifact.prefix", "FastAsyncWorldEdit-Paper");
        String suffix = getConfig().getString("artifact.suffix", ".jar");

        Artifact artifact = findArtifactInJson(json, prefix, suffix);
        if (artifact == null) {
            throw new IOException("Подходящий артефакт не найден в JSON ответе.");
        }

        String downloadUrl = String.format("%s%s/%s/artifact/%s",
                baseUrl.replaceAll("/$", ""), jobPath, buildRef, artifact.relativePath);

        Path pluginsDir = Paths.get("plugins");
        Path updateDir = pluginsDir.resolve("update");
        boolean useUpdateFolder = getConfig().getBoolean("target.useUpdateFolder", true);
        Path downloadDir = useUpdateFolder ? updateDir : pluginsDir;

        String targetJarName = getConfig().getString("target.jarName", "");
        if (targetJarName.isEmpty())
            targetJarName = detectInstalledFaweJarName();

        Files.createDirectories(downloadDir);
        Path destFile = downloadDir.resolve(targetJarName);
        Path tempFile = downloadDir.resolve(targetJarName + ".tmp");

        if (useUpdateFolder && Files.exists(destFile) && Files.size(destFile) > 1024) {
            getLogger().info("Обновление " + remoteBuildNumber + " уже скачано. Ожидание перезагрузки.");
            return;
        }

        getLogger().info("Скачивание: " + artifact.fileName);

        HttpClient.downloadFile(this, downloadUrl, tempFile);

        try {
            Files.move(tempFile, destFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(tempFile, destFile, StandardCopyOption.REPLACE_EXISTING);
        }

        updateState(remoteBuildNumber, artifact.fileName);
        getLogger().info("Успешно скачан билд " + remoteBuildNumber + ". Перезапустите сервер.");
    }

    private static class HttpClient {

        static String fetchString(FAWEUpdater plugin, String url) throws IOException {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            executeRequest(plugin, url, out);
            return new String(out.toByteArray(), StandardCharsets.UTF_8);
        }

        static void downloadFile(FAWEUpdater plugin, String url, Path destFile) throws IOException {
            try (OutputStream fileOut = Files.newOutputStream(destFile)) {
                executeRequest(plugin, url, fileOut);
            }
        }

        private static void executeRequest(FAWEUpdater plugin, String initialUrl, OutputStream outputStream)
                throws IOException {
            String currentUrl = initialUrl;
            int redirects = 0;
            final int MAX_REDIRECTS = 5;

            while (redirects < MAX_REDIRECTS) {
                URI uri = URI.create(currentUrl.replace(" ", "%20"));
                String host = uri.getHost();
                int port = uri.getPort() != -1 ? uri.getPort() : (uri.getScheme().equals("https") ? 443 : 80);
                String rawPath = uri.getRawPath() + (uri.getRawQuery() != null ? "?" + uri.getRawQuery() : "");

                try (Socket socket = connectSocket(plugin, host, port)) {
                    sendRequestHeaders(socket, host, rawPath);

                    InputStream in = new BufferedInputStream(socket.getInputStream());
                    String statusLine = readLine(in);
                    if (statusLine == null)
                        throw new IOException("Пустой ответ от сервера");

                    int statusCode = parseStatusCode(statusLine);
                    Map<String, String> headers = readHeaders(in);

                    if (isRedirect(statusCode)) {
                        String location = headers.get("location");
                        if (location == null)
                            throw new IOException("Редирект без заголовка Location");

                        if (!location.startsWith("http")) {
                            currentUrl = uri.resolve(location).toString();
                        } else {
                            currentUrl = location;
                        }
                        redirects++;
                        continue;
                    }

                    if (statusCode != 200) {
                        throw new IOException("HTTP ошибка " + statusCode + " URL: " + currentUrl);
                    }

                    readResponseBody(in, headers, outputStream);
                    return;
                }
            }
            throw new IOException("Слишком много редиректов");
        }

        private static Socket connectSocket(FAWEUpdater plugin, String targetHost, int targetPort) throws IOException {
            boolean proxyEnabled = plugin.getConfig().getBoolean("proxy.enabled", false);
            int connectTimeout = plugin.getConfig().getInt("network.connectTimeoutMillis", 10000);
            int readTimeout = plugin.getConfig().getInt("network.readTimeoutMillis", 60000);

            if (proxyEnabled) {
                String proxyHost = plugin.getConfig().getString("proxy.host", "127.0.0.1");
                int proxyPort = plugin.getConfig().getInt("proxy.port", 3128);
                String proxyUser = plugin.getConfig().getString("proxy.username", "");
                String proxyPass = plugin.getConfig().getString("proxy.password", "");

                Socket s = new Socket();
                s.connect(new InetSocketAddress(proxyHost, proxyPort), connectTimeout);
                s.setSoTimeout(readTimeout);

                OutputStream out = s.getOutputStream();
                StringBuilder connect = new StringBuilder();
                connect.append("CONNECT ").append(targetHost).append(":").append(targetPort).append(" HTTP/1.1\r\n");
                connect.append("Host: ").append(targetHost).append(":").append(targetPort).append("\r\n");

                if (!proxyUser.isEmpty() || !proxyPass.isEmpty()) {
                    String auth = proxyUser + ":" + proxyPass;
                    String encoded = Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.ISO_8859_1));
                    connect.append("Proxy-Authorization: Basic ").append(encoded).append("\r\n");
                }
                connect.append("\r\n");

                out.write(connect.toString().getBytes(StandardCharsets.ISO_8859_1));
                out.flush();

                InputStream in = s.getInputStream();
                String status = readLine(in);
                if (status == null || !status.contains("200")) {
                    throw new IOException("Ошибка подключения к прокси: " + status);
                }
                while ((status = readLine(in)) != null && !status.isEmpty()) {
                }

                SSLSocketFactory ssf = (SSLSocketFactory) SSLSocketFactory.getDefault();
                SSLSocket sslSocket = (SSLSocket) ssf.createSocket(s, targetHost, targetPort, true);
                sslSocket.startHandshake();
                return sslSocket;
            } else {
                SSLSocketFactory ssf = (SSLSocketFactory) SSLSocketFactory.getDefault();
                SSLSocket sslSocket = (SSLSocket) ssf.createSocket();
                sslSocket.connect(new InetSocketAddress(targetHost, targetPort), connectTimeout);
                sslSocket.setSoTimeout(readTimeout);
                sslSocket.startHandshake();
                return sslSocket;
            }
        }

        private static void sendRequestHeaders(Socket socket, String host, String path) throws IOException {
            OutputStream out = socket.getOutputStream();
            StringBuilder req = new StringBuilder();
            req.append("GET ").append(path).append(" HTTP/1.1\r\n");
            req.append("Host: ").append(host).append("\r\n");
            req.append("User-Agent: FAWE-Updater\r\n");
            req.append("Connection: close\r\n");
            req.append("\r\n");
            out.write(req.toString().getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
        }

        private static Map<String, String> readHeaders(InputStream in) throws IOException {
            Map<String, String> headers = new HashMap<>();
            String line;
            while ((line = readLine(in)) != null && !line.isEmpty()) {
                int idx = line.indexOf(':');
                if (idx > 0) {
                    headers.put(line.substring(0, idx).trim().toLowerCase(), line.substring(idx + 1).trim());
                }
            }
            return headers;
        }

        private static void readResponseBody(InputStream in, Map<String, String> headers, OutputStream out)
                throws IOException {
            boolean chunked = "chunked".equalsIgnoreCase(headers.get("transfer-encoding"));
            String cl = headers.get("content-length");

            if (chunked) {
                readChunkedStream(in, out);
            } else if (cl != null) {
                long len = Long.parseLong(cl);
                byte[] buf = new byte[8192];
                long total = 0;
                while (total < len) {
                    int read = in.read(buf, 0, (int) Math.min(buf.length, len - total));
                    if (read == -1)
                        break;
                    out.write(buf, 0, read);
                    total += read;
                }
            } else {
                byte[] buf = new byte[8192];
                int read;
                while ((read = in.read(buf)) != -1) {
                    out.write(buf, 0, read);
                }
            }
        }

        private static void readChunkedStream(InputStream in, OutputStream out) throws IOException {
            while (true) {
                String line = readLine(in);
                if (line == null)
                    break;
                line = line.trim();
                if (line.isEmpty())
                    continue;

                int size = Integer.parseInt(line, 16);
                if (size == 0)
                    break;

                byte[] buf = new byte[size];
                int total = 0;
                while (total < size) {
                    int read = in.read(buf, total, size - total);
                    if (read == -1)
                        throw new IOException("Неожиданный конец потока в середине чанка");
                    total += read;
                }
                out.write(buf);
                readLine(in);
            }
        }

        private static String readLine(InputStream in) throws IOException {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            int b;
            while ((b = in.read()) != -1) {
                if (b == '\n')
                    break;
                if (b != '\r')
                    buf.write(b);
            }
            if (b == -1 && buf.size() == 0)
                return null;
            return buf.toString(StandardCharsets.ISO_8859_1.name());
        }

        private static int parseStatusCode(String statusLine) {
            try {
                String[] parts = statusLine.split(" ");
                if (parts.length > 1)
                    return Integer.parseInt(parts[1]);
            } catch (Exception ignored) {
            }
            return 500;
        }

        private static boolean isRedirect(int code) {
            return code == 301 || code == 302 || code == 303 || code == 307 || code == 308;
        }
    }

    private long parseBuildNumberFromJson(String json) {
        Matcher m = JSON_BUILD_NUM_PATTERN.matcher(json);
        return m.find() ? Long.parseLong(m.group(1)) : -1;
    }

    private Artifact findArtifactInJson(String json, String prefix, String suffix) {
        int idx = json.indexOf("\"artifacts\"");
        if (idx == -1)
            return null;

        String part = json.substring(idx);
        Matcher fm = Pattern.compile("\"fileName\"\\s*:\\s*\"([^\"]+)\"").matcher(part);
        Matcher pm = Pattern.compile("\"relativePath\"\\s*:\\s*\"([^\"]+)\"").matcher(part);

        while (fm.find() && pm.find()) {
            String f = fm.group(1);
            if (f.startsWith(prefix) && f.endsWith(suffix)) {
                return new Artifact(f, pm.group(1));
            }
        }
        return null;
    }

    private long getInstalledFaweBuildNumber() {
        Plugin p = getServer().getPluginManager().getPlugin("FastAsyncWorldEdit");
        if (p == null)
            return -1;
        String version = p.getPluginMeta().getVersion();
        Matcher m = BUILD_NUMBER_PATTERN.matcher(version);
        if (m.find()) {
            try {
                return Long.parseLong(m.group(1));
            } catch (NumberFormatException ignored) {
            }
        }
        return -1;
    }

    private String detectInstalledFaweJarName() {
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(Paths.get("plugins"), "*.jar")) {
            for (Path p : ds) {
                String n = p.getFileName().toString();
                if (n.startsWith("FastAsyncWorldEdit") && !n.endsWith(".tmp"))
                    return n;
            }
        } catch (IOException ignored) {
        }
        return "FastAsyncWorldEdit.jar";
    }

    private void updateState(long build, String file) {
        Properties p = new Properties();
        p.setProperty("lastBuildNumber", String.valueOf(build));
        p.setProperty("lastArtifactFileName", file);
        try (OutputStream out = Files.newOutputStream(getDataFolder().toPath().resolve(STATE_FILE_NAME))) {
            p.store(out, null);
        } catch (IOException ignored) {
        }
    }

    private static class Artifact {
        final String fileName;
        final String relativePath;

        Artifact(String f, String r) {
            this.fileName = f;
            this.relativePath = r;
        }
    }

    @Override
    public void onDisable() {
        if (!getConfig().getBoolean("enabled", true)) {
            return;
        }

        try {
            doUpdate();
        } catch (Exception e) {
            getLogger().log(Level.SEVERE, "Ошибка обновления FAWE при выключении", e);
        }
    }

}