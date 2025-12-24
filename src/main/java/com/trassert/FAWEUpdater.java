package com.trassert;

import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.scheduler.BukkitRunnable;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public final class FAWEUpdater extends JavaPlugin {

    private static final String STATE_FILE_NAME = "state.properties";

    @Override
    public void onEnable() {
        saveDefaultConfig();

        if (!getConfig().getBoolean("enabled", true)) {
            getLogger().info("FAWEUpdater выключен в конфиге (enabled: false).");
            return;
        }

        new BukkitRunnable() {
            @Override
            public void run() {
                try {
                    doUpdate();
                } catch (Exception e) {
                    getLogger().log(java.util.logging.Level.SEVERE, "Ошибка обновления FAWE", e);
                }
            }
        }.runTaskAsynchronously(this);
    }

    private void doUpdate() throws Exception {
        String baseUrl = getConfig().getString("jenkins.baseUrl", "https://ci.athion.net").trim();
        String jobPath = getConfig().getString("jenkins.jobPath", "/job/FastAsyncWorldEdit").trim();
        String buildRef = getConfig().getString("jenkins.build", "lastSuccessfulBuild").trim();

        String prefix = getConfig().getString("artifact.prefix", "FastAsyncWorldEdit-Paper");
        String suffix = getConfig().getString("artifact.suffix", ".jar");

        boolean useUpdateFolder = getConfig().getBoolean("target.useUpdateFolder", true);
        String targetJarNameCfg = getConfig().getString("target.jarName", "").trim();

        int connectTimeoutMillis = getConfig().getInt("network.connectTimeoutMillis", 10_000);
        int readTimeoutMillis = getConfig().getInt("network.readTimeoutMillis", 30_000);
        int maxRedirects = getConfig().getInt("network.maxRedirects", 5);

        boolean upToDateCheckEnabled = getBooleanOrDefault("upToDateCheck.enabled", true);
        long minValidJarSizeBytes = getLongOrDefault("upToDateCheck.minValidJarSizeBytes", 128L * 1024L);

        validateTimeouts(connectTimeoutMillis, readTimeoutMillis);

        Properties state = loadState();
        long lastBuildNumber = parseLong(state.getProperty("lastBuildNumber", "-1"), -1);
        String lastArtifactFileName = state.getProperty("lastArtifactFileName", "");
        String lastTargetJarName = state.getProperty("lastTargetJarName", "");

        URI apiUri = joinUri(baseUrl, jobPath, "/" + buildRef + "/api/json");
        getLogger().info("Запрос Jenkins JSON: " + apiUri);

        Map<String, String> jsonHeaders = new HashMap<>();
        jsonHeaders.put("Accept", "application/json");

        String json = httpGetTextFollowRedirects(apiUri, maxRedirects, jsonHeaders);

        // В Jenkins JSON поле number есть на верхнем уровне (build number). Вложенных
        // "number" тоже много,
        // поэтому берём только top-level.
        long remoteBuildNumber = getTopLevelJsonLongValue(json, "number", -1);

        Artifact artifact = pickArtifactFromJenkinsJsonTopLevel(json, prefix, suffix);
        if (artifact == null) {
            throw new IOException("Не найден артефакт по шаблону: prefix=" + prefix + ", suffix=" + suffix);
        }

        String relativePath = (artifact.relativePath != null && !artifact.relativePath.isEmpty())
                ? artifact.relativePath
                : ("artifacts/" + artifact.fileName);

        URI downloadUri = joinUri(baseUrl, jobPath, "/" + buildRef + "/artifact/" + encodePath(relativePath));

        getLogger().info("Найден артефакт: " + artifact.fileName);
        if (remoteBuildNumber >= 0) {
            getLogger().info("Remote build number: " + remoteBuildNumber);
        } else {
            getLogger().warning("Не удалось определить remote build number из Jenkins JSON (будет fallback логика).");
        }

        String targetJarName = !targetJarNameCfg.isEmpty() ? targetJarNameCfg : detectInstalledFaweJarName();
        if (targetJarName == null || targetJarName.trim().isEmpty())
            targetJarName = "FastAsyncWorldEdit.jar";

        Path pluginsDir = Paths.get("plugins");
        Files.createDirectories(pluginsDir);

        // ВАЖНО:
        // - Если useUpdateFolder=true, скачиваем в plugins/update/<jarName>, но
        // актуальность надо проверять
        // по УСТАНОВЛЕННОМУ файлу plugins/<jarName>, иначе будет скачивать на каждом
        // старте.
        Path installedJar = pluginsDir.resolve(targetJarName);
        Path updateDir = pluginsDir.resolve("update");
        Path pendingJar = updateDir.resolve(targetJarName);

        Path downloadDir = useUpdateFolder ? updateDir : pluginsDir;
        Files.createDirectories(downloadDir);

        Path dest = downloadDir.resolve(targetJarName);
        Path tmp = downloadDir.resolve(targetJarName + ".tmp");

        if (upToDateCheckEnabled) {
            long installedBuildFromPlugin = getInstalledFaweBuildNumberFromPlugin();
            if (installedBuildFromPlugin >= 0 && remoteBuildNumber >= 0) {
                if (installedBuildFromPlugin >= remoteBuildNumber) {
                    getLogger().info("FAWE уже актуален (installed build " + installedBuildFromPlugin +
                            " >= remote build " + remoteBuildNumber + "). Скачивание не требуется.");
                    return;
                }
            }

            // Если плагин уже обновлялся этим апдейтером (state) — проверяем установленный
            // jar (plugins/),
            // а также "pending" jar (plugins/update/) на всякий случай.
            boolean sameRemoteAsState = (remoteBuildNumber >= 0 && remoteBuildNumber == lastBuildNumber)
                    || (remoteBuildNumber < 0 && lastBuildNumber >= 0); // если remote неизвестен, не делаем строгих
                                                                        // выводов

            boolean sameArtifactAsState = artifact.fileName.equals(lastArtifactFileName);
            boolean sameTargetAsState = targetJarName.equals(lastTargetJarName) || lastTargetJarName.isEmpty();

            if (remoteBuildNumber >= 0 && sameRemoteAsState && sameArtifactAsState && sameTargetAsState) {
                if (isLooksLikeValidJar(installedJar, minValidJarSizeBytes)) {
                    getLogger().info(
                            "FAWE уже актуален (по state + установленному jar, build " + remoteBuildNumber + ").");
                    return;
                }
                if (useUpdateFolder && isLooksLikeValidJar(pendingJar, minValidJarSizeBytes)) {
                    getLogger().info("FAWE уже скачан (pending) в plugins/update и ожидает рестарта (build "
                            + remoteBuildNumber + ").");
                    return;
                }
            }
        }

        getLogger().info("Скачивание: " + downloadUri);
        getLogger().info("Сохранение в: " + tmp.toAbsolutePath());

        Map<String, String> binHeaders = new HashMap<>();
        binHeaders.put("Accept", "application/octet-stream");

        httpDownloadToFileFollowRedirects(downloadUri, tmp, maxRedirects, binHeaders);

        long size = Files.size(tmp);
        if (size < minValidJarSizeBytes) {
            throw new IOException("Скачанный файл подозрительно маленький (" + size + " байт).");
        }

        try {
            Files.move(tmp, dest, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException ignored) {
            Files.move(tmp, dest, StandardCopyOption.REPLACE_EXISTING);
        }

        // сохраняем state
        if (remoteBuildNumber >= 0) {
            state.setProperty("lastBuildNumber", Long.toString(remoteBuildNumber));
        } else {
            // не затираем последнюю известную цифру на -1; оставим как есть
            state.putIfAbsent("lastBuildNumber", Long.toString(lastBuildNumber));
        }
        state.setProperty("lastArtifactFileName", artifact.fileName);
        state.setProperty("lastTargetJarName", targetJarName);
        saveState(state);

        if (useUpdateFolder) {
            getLogger().info("Готово. Обновление лежит в plugins/update/" + targetJarName + ". Перезапусти сервер.");
        } else {
            getLogger().info("Готово. Файл заменён: plugins/" + targetJarName + ". Перезапусти сервер.");
        }
    }

    private boolean isLooksLikeValidJar(Path file, long minSize) {
        try {
            return Files.isRegularFile(file) && Files.size(file) >= minSize;
        } catch (IOException e) {
            return false;
        }
    }

    private long getInstalledFaweBuildNumberFromPlugin() {
        try {
            Plugin p = getServer().getPluginManager().getPlugin("FastAsyncWorldEdit");
            if (p == null)
                return -1;
            String version = p.getPluginMeta().getVersion();
            return extractTrailingNumber(version);
        } catch (Exception ignored) {
            return -1;
        }
    }

    private long extractTrailingNumber(String s) {
        if (s == null || s.isEmpty())
            return -1;

        int i = s.length() - 1;
        while (i >= 0 && !Character.isDigit(s.charAt(i)))
            i--;
        if (i < 0)
            return -1;

        int end = i;
        while (i >= 0 && Character.isDigit(s.charAt(i)))
            i--;
        int start = i + 1;

        if (start > end)
            return -1;
        try {
            return Long.parseLong(s.substring(start, end + 1));
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private boolean getBooleanOrDefault(String path, boolean def) {
        if (!getConfig().contains(path))
            return def;
        return getConfig().getBoolean(path);
    }

    private long getLongOrDefault(String path, long def) {
        if (!getConfig().contains(path))
            return def;
        try {
            return getConfig().getLong(path);
        } catch (Exception e) {
            return def;
        }
    }

    private void validateTimeouts(int connectTimeoutMillis, int readTimeoutMillis) {
        if (connectTimeoutMillis < 1)
            throw new IllegalArgumentException("network.connectTimeoutMillis < 1");
        if (readTimeoutMillis < 1)
            throw new IllegalArgumentException("network.readTimeoutMillis < 1");
    }

    private Properties loadState() {
        Properties p = new Properties();
        try {
            Files.createDirectories(getDataFolder().toPath());
            Path f = getDataFolder().toPath().resolve(STATE_FILE_NAME);
            if (!Files.isRegularFile(f))
                return p;
            try (InputStream in = Files.newInputStream(f)) {
                p.load(in);
            }
        } catch (Exception ignored) {
        }
        return p;
    }

    private void saveState(Properties p) {
        try {
            Files.createDirectories(getDataFolder().toPath());
            Path f = getDataFolder().toPath().resolve(STATE_FILE_NAME);
            try (OutputStream out = Files.newOutputStream(f, StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                p.store(out, "FAWEUpdater state");
            }
        } catch (Exception ignored) {
        }
    }

    private long parseLong(String s, long def) {
        if (s == null)
            return def;
        try {
            return Long.parseLong(s.trim());
        } catch (NumberFormatException e) {
            return def;
        }
    }

    private String detectInstalledFaweJarName() {
        Path pluginsDir = Paths.get("plugins");
        Path exact = pluginsDir.resolve("FastAsyncWorldEdit.jar");
        if (Files.isRegularFile(exact))
            return exact.getFileName().toString();

        try (DirectoryStream<Path> ds = Files.newDirectoryStream(pluginsDir, "*.jar")) {
            List<String> matches = new ArrayList<>();
            for (Path p : ds) {
                String name = p.getFileName().toString();
                if (name.startsWith("FastAsyncWorldEdit") && name.endsWith(".jar") && !name.endsWith(".tmp")) {
                    matches.add(name);
                }
            }
            if (matches.size() == 1)
                return matches.get(0);
        } catch (IOException ignored) {
        }

        return "FastAsyncWorldEdit.jar";
    }

    private URI joinUri(String baseUrl, String... parts) {
        String b = baseUrl.trim();
        while (b.endsWith("/"))
            b = b.substring(0, b.length() - 1);

        StringBuilder sb = new StringBuilder(b);
        for (String raw : parts) {
            if (raw == null || raw.isEmpty())
                continue;
            String p = raw.trim();
            if (!p.startsWith("/"))
                sb.append('/');
            sb.append(p);
        }
        return URI.create(sb.toString());
    }

    private String encodePath(String path) {
        String[] segs = path.split("/");
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < segs.length; i++) {
            if (i > 0)
                out.append('/');
            out.append(URLEncoder.encode(segs[i], StandardCharsets.UTF_8).replace("+", "%20"));
        }
        return out.toString();
    }

    private String httpGetTextFollowRedirects(URI uri, int maxRedirects, Map<String, String> extraHeaders)
            throws IOException {
        URI current = uri;
        for (int i = 0; i <= maxRedirects; i++) {
            SimpleHttpResponse resp = httpRequest(current, "GET", extraHeaders);
            try {
                if (isRedirect(resp.statusCode)) {
                    String loc = resp.header("location");
                    if (loc == null)
                        throw new IOException("Редирект без Location, status=" + resp.statusCode);
                    current = current.resolve(loc);
                    continue;
                }
                if (resp.statusCode != 200) {
                    throw new IOException("HTTP " + resp.statusCode + " при GET " + current);
                }
                byte[] body = resp.readBodyFully();
                return new String(body, StandardCharsets.UTF_8);
            } finally {
                resp.close();
            }
        }
        throw new IOException("Слишком много редиректов: " + uri);
    }

    private void httpDownloadToFileFollowRedirects(URI uri, Path dest, int maxRedirects,
            Map<String, String> extraHeaders) throws IOException {
        URI current = uri;
        for (int i = 0; i <= maxRedirects; i++) {
            SimpleHttpResponse resp = httpRequest(current, "GET", extraHeaders);
            try {
                if (isRedirect(resp.statusCode)) {
                    String loc = resp.header("location");
                    if (loc == null)
                        throw new IOException("Редирект без Location, status=" + resp.statusCode);
                    current = current.resolve(loc);
                    continue;
                }

                if (resp.statusCode != 200) {
                    throw new IOException("HTTP " + resp.statusCode + " при скачивании " + current);
                }

                Files.createDirectories(dest.getParent());
                resp.streamBodyToFile(dest);
                return;
            } finally {
                resp.close();
            }
        }
        throw new IOException("Слишком много редиректов: " + uri);
    }

    private boolean isRedirect(int code) {
        return code == 301 || code == 302 || code == 303 || code == 307 || code == 308;
    }

    private SimpleHttpResponse httpRequest(URI uri, String method, Map<String, String> extraHeaders)
            throws IOException {
        if (uri == null)
            throw new IllegalArgumentException("uri == null");
        if (method == null || method.isBlank())
            throw new IllegalArgumentException("method == null/blank");

        String scheme = uri.getScheme();
        if (scheme == null || (!scheme.equalsIgnoreCase("https") && !scheme.equalsIgnoreCase("http"))) {
            throw new IOException("Поддерживаются только http/https: " + uri);
        }

        String host = uri.getHost();
        if (host == null || host.isEmpty())
            throw new IOException("Некорректный host: " + uri);

        int port = uri.getPort();
        if (port == -1)
            port = scheme.equalsIgnoreCase("https") ? 443 : 80;

        String path = uri.getRawPath();
        if (path == null || path.isEmpty())
            path = "/";
        String query = uri.getRawQuery();
        if (query != null && !query.isEmpty())
            path = path + "?" + query;

        boolean https = scheme.equalsIgnoreCase("https");

        Socket socket = https ? openSslSocket(host, port) : openPlainSocket(host, port);
        socket.setSoTimeout(getConfig().getInt("network.readTimeoutMillis", 30_000));

        OutputStream out = socket.getOutputStream();

        StringBuilder req = new StringBuilder(256);
        req.append(method).append(' ').append(path).append(" HTTP/1.1\r\n");
        req.append("Host: ").append(host).append("\r\n");
        req.append("User-Agent: FAWE-Updater/1.3\r\n");
        req.append("Accept: */*\r\n");
        req.append("Accept-Encoding: identity\r\n");
        req.append("Connection: close\r\n");

        if (extraHeaders != null) {
            for (Map.Entry<String, String> e : extraHeaders.entrySet()) {
                if (e.getKey() == null || e.getKey().isBlank())
                    continue;
                if (e.getValue() == null)
                    continue;
                req.append(e.getKey().trim()).append(": ").append(e.getValue()).append("\r\n");
            }
        }

        req.append("\r\n");

        out.write(req.toString().getBytes(StandardCharsets.ISO_8859_1));
        out.flush();

        InputStream in = socket.getInputStream();
        String statusLine = readLine(in);
        if (statusLine == null) {
            closeQuietly(socket);
            throw new IOException("Пустой ответ от сервера: " + uri);
        }

        int statusCode = parseStatusCode(statusLine);

        Map<String, String> headers = new HashMap<>();
        while (true) {
            String line = readLine(in);
            if (line == null)
                break;
            if (line.isEmpty())
                break;
            int idx = line.indexOf(':');
            if (idx <= 0)
                continue;
            String key = line.substring(0, idx).trim().toLowerCase(Locale.ROOT);
            String val = line.substring(idx + 1).trim();
            headers.putIfAbsent(key, val);
        }

        return new SimpleHttpResponse(socket, in, statusCode, headers);
    }

    private int parseStatusCode(String statusLine) throws IOException {
        int sp1 = statusLine.indexOf(' ');
        if (sp1 == -1)
            throw new IOException("Некорректная status line: " + statusLine);
        int sp2 = statusLine.indexOf(' ', sp1 + 1);
        String codeStr = (sp2 == -1)
                ? statusLine.substring(sp1 + 1).trim()
                : statusLine.substring(sp1 + 1, sp2).trim();
        try {
            return Integer.parseInt(codeStr);
        } catch (NumberFormatException e) {
            throw new IOException("Не удалось распарсить HTTP status code из: " + statusLine);
        }
    }

    private Socket openPlainSocket(String host, int port) throws IOException {
        boolean proxyEnabled = getConfig().getBoolean("proxy.enabled", false);
        int connectTimeoutMillis = getConfig().getInt("network.connectTimeoutMillis", 10_000);

        if (!proxyEnabled) {
            Socket s = new Socket();
            s.connect(new InetSocketAddress(host, port), connectTimeoutMillis);
            return s;
        }

        throw new IOException("HTTP через прокси не реализован. Используй https URL.");
    }

    private SSLSocket openSslSocket(String host, int port) throws IOException {
        boolean proxyEnabled = getConfig().getBoolean("proxy.enabled", false);
        int connectTimeoutMillis = getConfig().getInt("network.connectTimeoutMillis", 10_000);
        int readTimeoutMillis = getConfig().getInt("network.readTimeoutMillis", 30_000);

        if (!proxyEnabled) {
            SSLSocket ssl = (SSLSocket) SSLSocketFactory.getDefault().createSocket(host, port);
            ssl.setSoTimeout(readTimeoutMillis);
            ssl.startHandshake();
            return ssl;
        }

        String proxyHost = getConfig().getString("proxy.host", "127.0.0.1");
        int proxyPort = getConfig().getInt("proxy.port", 3128);
        String username = getConfig().getString("proxy.username", "").trim();
        String password = getConfig().getString("proxy.password", "").trim();

        Socket tunnel = new Socket();
        tunnel.connect(new InetSocketAddress(proxyHost, proxyPort), connectTimeoutMillis);
        tunnel.setSoTimeout(readTimeoutMillis);

        OutputStream out = tunnel.getOutputStream();

        StringBuilder connect = new StringBuilder();
        connect.append("CONNECT ").append(host).append(":").append(port).append(" HTTP/1.1\r\n");
        connect.append("Host: ").append(host).append(":").append(port).append("\r\n");
        connect.append("User-Agent: FAWE-Updater/1.3\r\n");

        if (!username.isEmpty() || !password.isEmpty()) {
            String credentials = username + ":" + password;
            String encoded = Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.ISO_8859_1));
            connect.append("Proxy-Authorization: Basic ").append(encoded).append("\r\n");
        }

        connect.append("Connection: close\r\n");
        connect.append("\r\n");

        out.write(connect.toString().getBytes(StandardCharsets.ISO_8859_1));
        out.flush();

        InputStream in = tunnel.getInputStream();
        String statusLine = readLine(in);
        if (statusLine == null) {
            closeQuietly(tunnel);
            throw new IOException("Прокси не вернул статусную строку на CONNECT");
        }

        int code = parseStatusCode(statusLine);
        if (code != 200) {
            StringBuilder hdr = new StringBuilder();
            String line;
            while ((line = readLine(in)) != null && !line.isEmpty()) {
                hdr.append(line).append('\n');
            }
            closeQuietly(tunnel);
            throw new IOException("CONNECT через прокси не удался: HTTP " + code + " (" + statusLine + ")\n" + hdr);
        }

        while (true) {
            String line = readLine(in);
            if (line == null || line.isEmpty())
                break;
        }

        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket ssl = (SSLSocket) factory.createSocket(tunnel, host, port, true);
        ssl.setSoTimeout(readTimeoutMillis);
        ssl.startHandshake();
        return ssl;
    }

    private String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(128);
        while (true) {
            int b = in.read();
            if (b == -1) {
                if (buf.size() == 0)
                    return null;
                break;
            }
            if (b == '\n')
                break;
            if (b != '\r')
                buf.write(b);
        }
        return buf.toString(StandardCharsets.ISO_8859_1.name());
    }

    private void closeQuietly(Socket s) {
        try {
            s.close();
        } catch (Exception ignored) {
        }
    }

    private static final class SimpleHttpResponse implements Closeable {
        private final Socket socket;
        private final InputStream bodyStream;
        final int statusCode;
        private final Map<String, String> headers;

        SimpleHttpResponse(Socket socket, InputStream bodyStream, int statusCode, Map<String, String> headers) {
            this.socket = socket;
            this.bodyStream = bodyStream;
            this.statusCode = statusCode;
            this.headers = headers;
        }

        String header(String nameLowerCase) {
            if (nameLowerCase == null)
                return null;
            return headers.get(nameLowerCase.toLowerCase(Locale.ROOT));
        }

        byte[] readBodyFully() throws IOException {
            ByteArrayOutputStream out = new ByteArrayOutputStream(16 * 1024);
            streamBody(out);
            return out.toByteArray();
        }

        void streamBodyToFile(Path dest) throws IOException {
            try (OutputStream fileOut = Files.newOutputStream(dest,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
                streamBody(fileOut);
                fileOut.flush();
            }
        }

        private void streamBody(OutputStream out) throws IOException {
            String te = header("transfer-encoding");
            String cl = header("content-length");

            if (te != null && te.toLowerCase(Locale.ROOT).contains("chunked")) {
                readChunked(bodyStream, out);
                return;
            }

            if (cl != null) {
                long len;
                try {
                    len = Long.parseLong(cl.trim());
                } catch (NumberFormatException e) {
                    len = -1;
                }
                if (len >= 0) {
                    copyExactly(bodyStream, out, len);
                    return;
                }
            }

            copyToEof(bodyStream, out);
        }

        @Override
        public void close() {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }

        private void copyToEof(InputStream in, OutputStream out) throws IOException {
            byte[] buf = new byte[8192];
            int r;
            while ((r = in.read(buf)) != -1) {
                out.write(buf, 0, r);
            }
        }

        private void copyExactly(InputStream in, OutputStream out, long len) throws IOException {
            byte[] buf = new byte[8192];
            long remaining = len;
            while (remaining > 0) {
                int toRead = (int) Math.min(buf.length, remaining);
                int r = in.read(buf, 0, toRead);
                if (r == -1)
                    throw new EOFException("EOF при чтении тела, ожидалось ещё " + remaining + " байт");
                out.write(buf, 0, r);
                remaining -= r;
            }
        }

        private void readChunked(InputStream in, OutputStream out) throws IOException {
            while (true) {
                String line = readLineStatic(in);
                if (line == null)
                    throw new EOFException("EOF при чтении chunk-size");
                line = line.trim();
                int semi = line.indexOf(';');
                String sizeStr = (semi >= 0) ? line.substring(0, semi).trim() : line;

                int size;
                try {
                    size = Integer.parseInt(sizeStr, 16);
                } catch (NumberFormatException e) {
                    throw new IOException("Некорректный chunk-size: " + line);
                }

                if (size == 0) {
                    while (true) {
                        String trailer = readLineStatic(in);
                        if (trailer == null || trailer.isEmpty())
                            break;
                    }
                    return;
                }

                copyExactly(in, out, size);

                int c1 = in.read();
                int c2 = in.read();
                if (c1 != '\r' || c2 != '\n') {
                    throw new IOException("Некорректное окончание chunk: ожидалось CRLF");
                }
            }
        }

        private String readLineStatic(InputStream in) throws IOException {
            ByteArrayOutputStream buf = new ByteArrayOutputStream(128);
            while (true) {
                int b = in.read();
                if (b == -1) {
                    if (buf.size() == 0)
                        return null;
                    break;
                }
                if (b == '\n')
                    break;
                if (b != '\r')
                    buf.write(b);
            }
            return buf.toString(StandardCharsets.ISO_8859_1.name());
        }
    }

    private static final class Artifact {
        final String fileName;
        final String relativePath;

        Artifact(String fileName, String relativePath) {
            this.fileName = fileName;
            this.relativePath = relativePath;
        }
    }

    // ----- Jenkins JSON parsing (без libs), аккуратно по top-level -----

    private Artifact pickArtifactFromJenkinsJsonTopLevel(String json, String prefix, String suffix) {
        if (json == null)
            return null;

        String artifactsArray = extractTopLevelJsonArrayByKey(json, "artifacts");
        if (artifactsArray == null)
            return null;

        List<String> objs = splitTopLevelJsonObjects(artifactsArray);
        for (String obj : objs) {
            String fileName = getJsonStringValue(obj, "fileName");
            if (fileName == null)
                continue;

            if (prefix != null && !prefix.isEmpty() && !fileName.startsWith(prefix))
                continue;
            if (suffix != null && !suffix.isEmpty() && !fileName.endsWith(suffix))
                continue;

            String rel = getJsonStringValue(obj, "relativePath");
            return new Artifact(fileName, rel);
        }
        return null;
    }

    private long getTopLevelJsonLongValue(String json, String key, long def) {
        if (json == null || key == null || key.isEmpty())
            return def;

        int i = 0;
        boolean inString = false;
        boolean esc = false;

        int objDepth = 0;
        int arrDepth = 0;

        while (i < json.length() && Character.isWhitespace(json.charAt(i)))
            i++;
        if (i >= json.length() || json.charAt(i) != '{')
            return def;

        for (; i < json.length(); i++) {
            char c = json.charAt(i);

            if (inString) {
                if (esc)
                    esc = false;
                else if (c == '\\')
                    esc = true;
                else if (c == '"')
                    inString = false;
                continue;
            }

            if (c == '"') {
                // ключи нас интересуют только на верхнем уровне объекта (objDepth == 1 и
                // arrDepth == 0)
                int keyStart = i + 1;
                inString = true;

                // прочитаем строку ключа
                int j = keyStart;
                boolean jEsc = false;
                StringBuilder sb = new StringBuilder();
                for (; j < json.length(); j++) {
                    char cc = json.charAt(j);
                    if (jEsc) {
                        sb.append(cc);
                        jEsc = false;
                        continue;
                    }
                    if (cc == '\\') {
                        jEsc = true;
                        continue;
                    }
                    if (cc == '"')
                        break;
                    sb.append(cc);
                }
                if (j >= json.length())
                    return def;

                String foundKey = sb.toString();
                inString = false;
                i = j; // сейчас на закрывающей кавычке

                // пробелы -> :
                int k = i + 1;
                while (k < json.length() && Character.isWhitespace(json.charAt(k)))
                    k++;
                if (k >= json.length() || json.charAt(k) != ':')
                    continue;

                // это точно key:value
                if (objDepth == 1 && arrDepth == 0 && foundKey.equals(key)) {
                    k++; // после :
                    while (k < json.length() && Character.isWhitespace(json.charAt(k)))
                        k++;
                    if (k >= json.length())
                        return def;

                    int start = k;
                    if (json.charAt(k) == '-')
                        k++;
                    while (k < json.length() && Character.isDigit(json.charAt(k)))
                        k++;

                    if (k == start || (k == start + 1 && json.charAt(start) == '-'))
                        return def;
                    try {
                        return Long.parseLong(json.substring(start, k));
                    } catch (NumberFormatException e) {
                        return def;
                    }
                }

                continue;
            }

            if (c == '{')
                objDepth++;
            else if (c == '}')
                objDepth--;
            else if (c == '[')
                arrDepth++;
            else if (c == ']')
                arrDepth--;

            if (objDepth <= 0)
                break;
        }

        return def;
    }

    private String extractTopLevelJsonArrayByKey(String json, String key) {
        if (json == null || key == null || key.isEmpty())
            return null;

        int i = 0;
        boolean inString = false;
        boolean esc = false;

        int objDepth = 0;
        int arrDepth = 0;

        while (i < json.length() && Character.isWhitespace(json.charAt(i)))
            i++;
        if (i >= json.length() || json.charAt(i) != '{')
            return null;

        for (; i < json.length(); i++) {
            char c = json.charAt(i);

            if (inString) {
                if (esc)
                    esc = false;
                else if (c == '\\')
                    esc = true;
                else if (c == '"')
                    inString = false;
                continue;
            }

            if (c == '"') {
                int keyStart = i + 1;
                inString = true;

                int j = keyStart;
                boolean jEsc = false;
                StringBuilder sb = new StringBuilder();
                for (; j < json.length(); j++) {
                    char cc = json.charAt(j);
                    if (jEsc) {
                        sb.append(cc);
                        jEsc = false;
                        continue;
                    }
                    if (cc == '\\') {
                        jEsc = true;
                        continue;
                    }
                    if (cc == '"')
                        break;
                    sb.append(cc);
                }
                if (j >= json.length())
                    return null;

                String foundKey = sb.toString();
                inString = false;
                i = j;

                int k = i + 1;
                while (k < json.length() && Character.isWhitespace(json.charAt(k)))
                    k++;
                if (k >= json.length() || json.charAt(k) != ':')
                    continue;

                if (objDepth == 1 && arrDepth == 0 && foundKey.equals(key)) {
                    k++;
                    while (k < json.length() && Character.isWhitespace(json.charAt(k)))
                        k++;
                    if (k >= json.length() || json.charAt(k) != '[')
                        return null;

                    int start = k;
                    int end = findMatchingBracket(json, start, '[', ']');
                    if (end == -1)
                        return null;

                    return json.substring(start + 1, end); // внутри []
                }

                continue;
            }

            if (c == '{')
                objDepth++;
            else if (c == '}')
                objDepth--;
            else if (c == '[')
                arrDepth++;
            else if (c == ']')
                arrDepth--;

            if (objDepth <= 0)
                break;
        }

        return null;
    }

    private int findMatchingBracket(String s, int startIndex, char open, char close) {
        boolean inString = false;
        boolean esc = false;
        int depth = 0;

        for (int i = startIndex; i < s.length(); i++) {
            char c = s.charAt(i);

            if (inString) {
                if (esc)
                    esc = false;
                else if (c == '\\')
                    esc = true;
                else if (c == '"')
                    inString = false;
                continue;
            }

            if (c == '"') {
                inString = true;
                continue;
            }

            if (c == open)
                depth++;
            if (c == close) {
                depth--;
                if (depth == 0)
                    return i;
            }
        }
        return -1;
    }

    private List<String> splitTopLevelJsonObjects(String arrayContent) {
        List<String> out = new ArrayList<>();
        boolean inString = false;
        boolean esc = false;
        int depth = 0;
        int start = -1;

        for (int i = 0; i < arrayContent.length(); i++) {
            char c = arrayContent.charAt(i);

            if (inString) {
                if (esc)
                    esc = false;
                else if (c == '\\')
                    esc = true;
                else if (c == '"')
                    inString = false;
                continue;
            }

            if (c == '"') {
                inString = true;
                continue;
            }

            if (c == '{') {
                if (depth == 0)
                    start = i;
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0 && start >= 0) {
                    out.add(arrayContent.substring(start, i + 1));
                    start = -1;
                }
            }
        }

        return out;
    }

    private String getJsonStringValue(String objJson, String key) {
        String needle = "\"" + key + "\"";
        int k = objJson.indexOf(needle);
        if (k == -1)
            return null;

        int colon = objJson.indexOf(':', k + needle.length());
        if (colon == -1)
            return null;

        int i = colon + 1;
        while (i < objJson.length() && Character.isWhitespace(objJson.charAt(i)))
            i++;
        if (i >= objJson.length() || objJson.charAt(i) != '"')
            return null;

        i++;
        StringBuilder sb = new StringBuilder();
        boolean esc = false;

        while (i < objJson.length()) {
            char c = objJson.charAt(i++);
            if (esc) {
                switch (c) {
                    case '"':
                        sb.append('"');
                        break;
                    case '\\':
                        sb.append('\\');
                        break;
                    case '/':
                        sb.append('/');
                        break;
                    case 'b':
                        sb.append('\b');
                        break;
                    case 'f':
                        sb.append('\f');
                        break;
                    case 'n':
                        sb.append('\n');
                        break;
                    case 'r':
                        sb.append('\r');
                        break;
                    case 't':
                        sb.append('\t');
                        break;
                    case 'u':
                        if (i + 4 <= objJson.length()) {
                            String hex = objJson.substring(i, i + 4);
                            try {
                                sb.append((char) Integer.parseInt(hex, 16));
                            } catch (NumberFormatException ignored) {
                            }
                            i += 4;
                        }
                        break;
                    default:
                        sb.append(c);
                }
                esc = false;
                continue;
            }

            if (c == '\\') {
                esc = true;
                continue;
            }
            if (c == '"') {
                return sb.toString();
            }
            sb.append(c);
        }
        return null;
    }
}