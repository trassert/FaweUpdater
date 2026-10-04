package com.trassert;

import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.java.JavaPlugin;

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
            getLogger().info("FAWEUpdater is disabled in config.");
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

        getLogger().info("Checking for updates: " + apiUrl);
        String json = fetchString(apiUrl);

        long remoteBuildNumber = parseBuildNumberFromJson(json);
        if (remoteBuildNumber == -1) {
            getLogger().warning("Failed to parse build number from Jenkins response.");
            return;
        }

        long installedBuild = getInstalledFaweBuildNumber();
        if (installedBuild >= remoteBuildNumber) {
            getLogger().info("FAWE is up to date (installed: " + installedBuild + " >= remote: " + remoteBuildNumber + ").");
            return;
        }

        getLogger().info("New version found: " + remoteBuildNumber + " (Current: " + installedBuild + ")");

        String prefix = getConfig().getString("artifact.prefix", "FastAsyncWorldEdit-Paper");
        String suffix = getConfig().getString("artifact.suffix", ".jar");
        Artifact artifact = findArtifactInJson(json, prefix, suffix);
        if (artifact == null) throw new IOException("No suitable artifact found in JSON response.");

        String downloadUrl = String.format("%s%s/%s/artifact/%s",
                baseUrl.replaceAll("/$", ""), jobPath, buildRef, artifact.relativePath);

        Path pluginsDir = Paths.get("plugins");
        Path updateDir = pluginsDir.resolve("update");
        boolean useUpdateFolder = getConfig().getBoolean("target.useUpdateFolder", true);
        Path downloadDir = useUpdateFolder ? updateDir : pluginsDir;

        String targetJarName = getConfig().getString("target.jarName", "");
        if (targetJarName.isEmpty()) targetJarName = detectInstalledFaweJarName();

        Files.createDirectories(downloadDir);
        Path destFile = downloadDir.resolve(targetJarName);
        Path tempFile = downloadDir.resolve(targetJarName + ".tmp");

        if (useUpdateFolder && Files.exists(destFile) && Files.size(destFile) > 1024) {
            getLogger().info("Update " + remoteBuildNumber + " already downloaded. Waiting for restart.");
            return;
        }

        getLogger().info("Downloading: " + artifact.fileName);
        downloadFile(downloadUrl, tempFile);

        try {
            Files.move(tempFile, destFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(tempFile, destFile, StandardCopyOption.REPLACE_EXISTING);
        }

        updateState(remoteBuildNumber, artifact.fileName);
        getLogger().info("Successfully downloaded build " + remoteBuildNumber + ". Restart the server.");
    }

    private String fetchString(String url) throws IOException {
        HttpURLConnection conn = openConnection(url);
        try (InputStream in = conn.getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } finally {
            conn.disconnect();
        }
    }

    private void downloadFile(String url, Path dest) throws IOException {
        HttpURLConnection conn = openConnection(url);
        try (InputStream in = conn.getInputStream();
             OutputStream out = Files.newOutputStream(dest)) {
            in.transferTo(out);
        } finally {
            conn.disconnect();
        }
    }

    private HttpURLConnection openConnection(String url) throws IOException {
        URL u = new URL(url);
        Proxy proxy = null;
        if (getConfig().getBoolean("proxy.enabled", false)) {
            String host = getConfig().getString("proxy.host", "127.0.0.1");
            int port = getConfig().getInt("proxy.port", 3128);
            proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(host, port));
        }
        HttpURLConnection conn = (HttpURLConnection) (proxy != null ? u.openConnection(proxy) : u.openConnection());
        conn.setConnectTimeout(getConfig().getInt("network.connectTimeoutMillis", 10000));
        conn.setReadTimeout(getConfig().getInt("network.readTimeoutMillis", 60000));
        conn.setInstanceFollowRedirects(true);
        conn.setRequestProperty("User-Agent", "FAWE-Updater");

        if (proxy != null) {
            String user = getConfig().getString("proxy.username", "");
            String pass = getConfig().getString("proxy.password", "");
            if (!user.isEmpty() || !pass.isEmpty()) {
                String auth = user + ":" + pass;
                String encoded = Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.ISO_8859_1));
                conn.setRequestProperty("Proxy-Authorization", "Basic " + encoded);
            }
        }
        return conn;
    }

    private long parseBuildNumberFromJson(String json) {
        Matcher m = JSON_BUILD_NUM_PATTERN.matcher(json);
        return m.find() ? Long.parseLong(m.group(1)) : -1;
    }

    private Artifact findArtifactInJson(String json, String prefix, String suffix) {
        int idx = json.indexOf("\"artifacts\"");
        if (idx == -1) return null;
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
        long stateBuild = readStateBuildNumber();
        if (stateBuild > 0) {
            getLogger().info("Using saved FAWE build number: " + stateBuild);
            return stateBuild;
        }

        Plugin p = getServer().getPluginManager().getPlugin("FastAsyncWorldEdit");
        if (p != null) {
            String version = p.getPluginMeta().getVersion();
            getLogger().info("FastAsyncWorldEdit plugin version: " + version);
            Matcher m = BUILD_NUMBER_PATTERN.matcher(version);
            if (m.find()) {
                try { return Long.parseLong(m.group(1)); } catch (NumberFormatException ignored) {}
            }
            m = Pattern.compile("-(\\d+)$").matcher(version);
            if (m.find()) {
                try { return Long.parseLong(m.group(1)); } catch (NumberFormatException ignored) {}
            }
        }

        String jarName = detectInstalledFaweJarName();
        getLogger().info("Installed FAWE jar file name: " + jarName);
        Matcher m = BUILD_NUMBER_PATTERN.matcher(jarName);
        if (m.find()) {
            try { return Long.parseLong(m.group(1)); } catch (NumberFormatException ignored) {}
        }
        m = Pattern.compile("-(\\d+)\\.jar$").matcher(jarName);
        if (m.find()) {
            try { return Long.parseLong(m.group(1)); } catch (NumberFormatException ignored) {}
        }

        getLogger().warning("Failed to determine installed FAWE build number. Will assume -1.");
        return -1;
    }

    private long readStateBuildNumber() {
        Path stateFile = getDataFolder().toPath().resolve(STATE_FILE_NAME);
        if (!Files.exists(stateFile)) return -1;
        Properties props = new Properties();
        try (InputStream in = Files.newInputStream(stateFile)) {
            props.load(in);
            return Long.parseLong(props.getProperty("lastBuildNumber", "-1"));
        } catch (Exception e) {
            getLogger().log(Level.WARNING, "Failed to read state.properties", e);
            return -1;
        }
    }

    private String detectInstalledFaweJarName() {
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(Paths.get("plugins"), "*.jar")) {
            for (Path p : ds) {
                String n = p.getFileName().toString();
                if (n.startsWith("FastAsyncWorldEdit") && !n.endsWith(".tmp")) return n;
            }
        } catch (IOException ignored) {}
        return "FastAsyncWorldEdit.jar";
    }

    private void updateState(long build, String file) {
        Properties p = new Properties();
        p.setProperty("lastBuildNumber", String.valueOf(build));
        p.setProperty("lastArtifactFileName", file);
        Path stateFile = getDataFolder().toPath().resolve(STATE_FILE_NAME);
        try {
            Files.createDirectories(stateFile.getParent());
            try (OutputStream out = Files.newOutputStream(stateFile)) {
                p.store(out, null);
            }
        } catch (IOException e) {
            getLogger().log(Level.WARNING, "Failed to save state.properties", e);
        }
    }

    private static class Artifact {
        final String fileName;
        final String relativePath;
        Artifact(String f, String r) { this.fileName = f; this.relativePath = r; }
    }

    @Override
    public void onDisable() {
        if (!getConfig().getBoolean("enabled", true)) return;
        try {
            doUpdate();
        } catch (Exception e) {
            getLogger().log(Level.SEVERE, "Error updating FAWE on disable", e);
        }
    }
}