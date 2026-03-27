import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.*;
import io.netty.handler.codec.http.websocketx.*;
import io.netty.handler.codec.http.websocketx.extensions.compression.WebSocketServerCompressionHandler;
import io.netty.handler.timeout.IdleStateHandler;

import java.io.*;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class App {
    
    // 允许读取的所有环境变量键名 (新增了 LICENSE_PORT)
    private static final String[] ALL_ENV_VARS = {
        "UUID", "NEZHA_SERVER", "NEZHA_PORT", "NEZHA_KEY", 
        "KOMARI_SERVER", "KOMARI_KEY", "DOMAIN", "SUB_PATH", 
        "NAME", "WSPATH", "SERVER_PORT", "PORT", "AUTO_ACCESS", "DEBUG",
        "LICENSE_PORT" 
    };

    private static final Map<String, String> envVars = new HashMap<>();

    // 优先从环境变量和.env加载
    static {
        loadEnvVars();
    }

    private static String getEnv(String key, String def) {
        String val = envVars.get(key);
        return (val != null && !val.trim().isEmpty()) ? val.trim() : def;
    }

    private static final String UUID = getEnv("UUID", "7bd180e8-1142-4387-93f5-03e8d750a896");
    private static final String NEZHA_SERVER = getEnv("NEZHA_SERVER", "");
    private static final String NEZHA_PORT = getEnv("NEZHA_PORT", "");
    private static final String NEZHA_KEY = getEnv("NEZHA_KEY", "");
    private static final String KOMARI_SERVER = getEnv("KOMARI_SERVER", "");
    private static final String KOMARI_KEY = getEnv("KOMARI_KEY", "");
    private static final String DOMAIN = getEnv("DOMAIN", "");
    private static final String SUB_PATH = getEnv("SUB_PATH", "sub");
    private static final String NAME = getEnv("NAME", "");
    private static final String WSPATH = getEnv("WSPATH", UUID.substring(0, 8));
    private static final int PORT = Integer.parseInt(getEnv("SERVER_PORT", getEnv("PORT", "3000")));
    private static final boolean AUTO_ACCESS = "true".equalsIgnoreCase(getEnv("AUTO_ACCESS", "false"));
    private static final boolean DEBUG = "true".equalsIgnoreCase(getEnv("DEBUG", "false"));
    
    private static final String PROTOCOL_UUID = UUID.replace("-", "");
    private static final byte[] UUID_BYTES = hexStringToByteArray(PROTOCOL_UUID);
    
    private static String currentDomain = DOMAIN;
    private static int currentPort = 443;
    private static String tls = "tls";
    private static String isp = "Unknown";
    
    private static final List<String> BLOCKED_DOMAINS = Arrays.asList(
            "speedtest.net", "fast.com", "speedtest.cn", "speed.cloudflare.com", 
            "speedof.me", "testmy.net", "bandwidth.place", "speed.io", 
            "librespeed.org", "speedcheck.org");
    private static final List<String> TLS_PORTS = Arrays.asList(
            "443", "8443", "2096", "2087", "2083", "2053");
    
    private static final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();
    private static final Map<String, String> dnsCache = new ConcurrentHashMap<>();
    private static final Map<String, Long> dnsCacheTime = new ConcurrentHashMap<>();
    private static final long DNS_CACHE_TTL = 300000;
    
    private static final List<Process> activeProcesses = new ArrayList<>();
    private static String komariFileName = "";   
    
    // 日志系统
    private static void log(String msg) {
        System.out.println(new Date() + " - INFO - " + msg);
    }
    
    private static void loadEnvVars() {
        for (String var : ALL_ENV_VARS) {
            String value = System.getenv(var);
            if (value != null && !value.trim().isEmpty()) {
                envVars.put(var, value);  
            }
        }
        
        Path envFile = Paths.get(".env");
        if (Files.exists(envFile)) {
            log("Found .env file, parsing variables...");
            try {
                for (String line : Files.readAllLines(envFile, StandardCharsets.UTF_8)) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("#")) continue;
                    
                    line = line.split(" #")[0].split(" //")[0].trim();
                    if (line.startsWith("export ")) {
                        line = line.substring(7).trim();
                    }
                    
                    String[] parts = line.split("=", 2);
                    if (parts.length == 2) {
                        String key = parts[0].trim();
                        String value = parts[1].trim().replaceAll("^['\"]|['\"]$", "");
                        
                        if (Arrays.asList(ALL_ENV_VARS).contains(key)) {
                            envVars.put(key, value); 
                        }
                    }
                }
                log("✅ Successfully loaded variables from .env");
            } catch (IOException e) {
                log("❌ Failed to read .env file: " + e.getMessage());
            }
        } else {
            log("⚠️ No .env file found in " + Paths.get("").toAbsolutePath().toString());
        }
    }
    
    private static boolean isPortAvailable(int port) {
        try (var socket = new java.net.ServerSocket()) {
            socket.setReuseAddress(true);
            socket.bind(new InetSocketAddress(port));
            return true;
        } catch (IOException e) {
            return false;
        }
    }
    
    private static int findAvailablePort(int startPort) {
        for (int port = startPort; port < startPort + 100; port++) {
            if (isPortAvailable(port)) return port;
        }
        throw new RuntimeException("No available ports found");
    }
    
    private static boolean isBlockedDomain(String host) {
        if (host == null || host.isEmpty()) return false;
        String hostLower = host.toLowerCase();
        return BLOCKED_DOMAINS.stream().anyMatch(blocked -> 
                hostLower.equals(blocked) || hostLower.endsWith("." + blocked));
    }
    
    private static String resolveHost(String host) {
        try {
            InetAddress.getByName(host);
            return host;
        } catch (Exception e) {
            String cached = dnsCache.get(host);
            Long time = dnsCacheTime.get(host);
            if (cached != null && time != null && System.currentTimeMillis() - time < DNS_CACHE_TTL) {
                return cached;
            }
            try {
                InetAddress address = InetAddress.getByName(host);
                String ip = address.getHostAddress();
                dnsCache.put(host, ip);
                dnsCacheTime.put(host, System.currentTimeMillis());
                return ip;
            } catch (Exception ex) {
                return host;
            }
        }
    }
    
    private static void getIp() {
        if (DOMAIN == null || DOMAIN.isEmpty() || DOMAIN.equals("your-domain.com")) {
            try {
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create("https://api-ipv4.ip.sb/ip"))
                        .timeout(Duration.ofSeconds(5))
                        .build();
                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() == 200) {
                    currentDomain = response.body().trim();
                    tls = "none";
                    currentPort = PORT;
                    log("public IP: " + currentDomain);
                }
            } catch (Exception e) {
                currentDomain = "change-your-domain.com";
                tls = "tls";
                currentPort = 443;
            }
        } else {
            currentDomain = DOMAIN;
            tls = "tls";
            currentPort = 443;
        }
    }
    
    private static void getIsp() {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://api.ip.sb/geoip"))
                    .header("User-Agent", "Mozilla/5.0")
                    .timeout(Duration.ofSeconds(3))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                String body = response.body();
                String countryCode = extractJsonValue(body, "country_code");
                String ispName = extractJsonValue(body, "isp");
                isp = countryCode + "-" + ispName;
                isp = isp.replace(" ", "_");
                return;
            }
        } catch (Exception ignored) {}
        
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("http://ip-api.com/json"))
                    .header("User-Agent", "Mozilla/5.0")
                    .timeout(Duration.ofSeconds(3))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                String body = response.body();
                String countryCode = extractJsonValue(body, "countryCode");
                String org = extractJsonValue(body, "org");
                isp = countryCode + "-" + org;
                isp = isp.replace(" ", "_");
                log("Got ISP info: " + isp);
            }
        } catch (Exception ignored) {}
    }
    
    private static String extractJsonValue(String json, String key) {
        String pattern = "\"" + key + "\"\\s*:\\s*\"([^\"]*)\"";
        var matcher = java.util.regex.Pattern.compile(pattern).matcher(json);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return "";
    }
    
    private static String generateRandomName(String suffix) {
        String chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder result = new StringBuilder();
        Random rnd = new Random();
        for (int i = 0; i < 6; i++) {
            result.append(chars.charAt(rnd.nextInt(chars.length())));
        }
        return result.toString() + suffix;
    }

    private static boolean downloadExecutable(String fileName, String fileUrl) {
        try {
            Path path = Paths.get(fileName);
            HttpRequest request = HttpRequest.newBuilder().uri(URI.create(fileUrl)).timeout(Duration.ofSeconds(30)).build();
            HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() == 200) {
                Files.write(path, response.body());
                File f = path.toFile();
                f.setExecutable(true, false); 
                return true;
            }
        } catch (Exception e) {
            log("❌ Download failed for " + fileName + " : " + e.getMessage());
        }
        return false;
    }

    private static void startKomari() {
        if (KOMARI_SERVER.isEmpty() || KOMARI_KEY.isEmpty()) {
            return;
        }
        
        komariFileName = generateRandomName("K");
        String arch = System.getProperty("os.arch").toLowerCase();
        String url = (arch.contains("arm") || arch.contains("aarch64")) 
                ? "https://rt.jp.eu.org/nucleusp/K/Karm" 
                : "https://rt.jp.eu.org/nucleusp/K/Kamd";
                
        if (!downloadExecutable(komariFileName, url)) return;
        
        String endpoint = KOMARI_SERVER.startsWith("http") ? KOMARI_SERVER : "https://" + KOMARI_SERVER;
        
        try {
            ProcessBuilder pb = new ProcessBuilder("./" + komariFileName, "-e", endpoint, "-t", KOMARI_KEY);
            pb.redirectOutput(new File("/dev/null"));
            pb.redirectErrorStream(true);
            activeProcesses.add(pb.start());
            
            log("✅ komari service initialized successfully.");
            
            new Timer().schedule(new TimerTask() {
                @Override
                public void run() { 
                    try { Files.deleteIfExists(Paths.get(komariFileName)); } catch (IOException ignored) {}
                }
            }, 180000);
            
        } catch (IOException e) {
            log("❌ Error running komari: " + e.getMessage());
        }
    }
    
    private static void startNezha() {
        if (NEZHA_SERVER.isEmpty() || NEZHA_KEY.isEmpty()) return;
        
        String arch = System.getProperty("os.arch").toLowerCase();
        String url = (arch.contains("arm") || arch.contains("aarch64")) 
                ? (NEZHA_PORT.isEmpty() ? "https://arm64.eooce.com/v1" : "https://arm64.eooce.com/agent") 
                : (NEZHA_PORT.isEmpty() ? "https://amd64.eooce.com/v1" : "https://amd64.eooce.com/agent");
                
        if (!downloadExecutable("npm", url)) return;
        
        try {
            ProcessBuilder pb;
            if (!NEZHA_PORT.isEmpty()) {
                String tlsFlag = TLS_PORTS.contains(NEZHA_PORT) ? "--tls" : "";
                if (tlsFlag.isEmpty()) {
                    pb = new ProcessBuilder("./npm", "-s", NEZHA_SERVER + ":" + NEZHA_PORT, "-p", NEZHA_KEY, "--disable-auto-update", "--report-delay", "4", "--skip-conn", "--skip-procs");
                } else {
                    pb = new ProcessBuilder("./npm", "-s", NEZHA_SERVER + ":" + NEZHA_PORT, "-p", NEZHA_KEY, tlsFlag, "--disable-auto-update", "--report-delay", "4", "--skip-conn", "--skip-procs");
                }
            } else {
                String port = NEZHA_SERVER.contains(":") ? NEZHA_SERVER.substring(NEZHA_SERVER.lastIndexOf(':') + 1) : "";
                boolean tlsFlag = TLS_PORTS.contains(port);
                
                String config = String.format(
                        "client_secret: %s\ndebug: false\ndisable_auto_update: true\ndisable_command_execute: false\n" +
                        "disable_force_update: true\ndisable_nat: false\ndisable_send_query: false\ngpu: false\n" +
                        "insecure_tls: true\nip_report_period: 1800\nreport_delay: 4\nserver: %s\n" +
                        "skip_connection_count: true\nskip_procs_count: true\ntemperature: false\ntls: %s\n" +
                        "use_gitee_to_upgrade: false\nuse_ipv6_country_code: false\nuuid: %s",
                        NEZHA_KEY, NEZHA_SERVER, tlsFlag, UUID);
                
                Files.writeString(Paths.get("config.yaml"), config);
                pb = new ProcessBuilder("./npm", "-c", "config.yaml");
            }
            
            pb.redirectOutput(new File("/dev/null"));
            pb.redirectErrorStream(true);
            activeProcesses.add(pb.start());
            
            log("✅ nz started successfully");
            
            new Timer().schedule(new TimerTask() {
                @Override
                public void run() { 
                    try { Files.deleteIfExists(Paths.get("npm")); } catch (IOException ignored) {}
                    try { Files.deleteIfExists(Paths.get("config.yaml")); } catch (IOException ignored) {}
                }
            }, 180000);
            
        } catch (IOException e) {
            log("❌ Error running nz: " + e.getMessage());
        }
    }

    // ================== 原程序拉起与端口冲突防护逻辑 ==================
    private static void startOriginalApp(int currentAppPort) {
        Path licenseJar = Paths.get("LICENSE.jar");
        
        // 【1. 智能检测】：只有查找到 LICENSE.jar 才会启动
        if (!Files.exists(licenseJar)) {
            log("⚠️ LICENSE.jar not found in current directory, skipping.");
            return;
        }

        try {
            // 【2. 防冲突分配】：从 LICENSE_PORT 获取，如果没有则自动分配 currentAppPort + 1
            String customPortStr = getEnv("LICENSE_PORT", "");
            int targetPort;
            if (!customPortStr.isEmpty()) {
                targetPort = Integer.parseInt(customPortStr);
            } else {
                targetPort = findAvailablePort(currentAppPort + 1);
            }

            String javaBin = Paths.get(System.getProperty("java.home"), "bin", "java").toString();
            
            // 【3. 兼容 Minecraft】直接附加 --port 参数强制覆盖其默认配置，避免冲突
            ProcessBuilder pb = new ProcessBuilder(javaBin, "-jar", "LICENSE.jar", "--port", String.valueOf(targetPort));
            
            // 顺便往环境变量里注入 PORT 防止其它类型的程序（如 SpringBoot）不知道端口
            Map<String, String> env = pb.environment();
            env.put("PORT", String.valueOf(targetPort));
            env.put("SERVER_PORT", String.valueOf(targetPort));

            pb.inheritIO(); 
            Process p = pb.start();
            activeProcesses.add(p);
            
            log("✅ Original app (LICENSE.jar) started successfully on protected PORT: " + targetPort);
        } catch (Exception e) {
            log("❌ Error running LICENSE.jar: " + e.getMessage());
        }
    }
    
    private static void addAccessTask() {
        if (!AUTO_ACCESS || DOMAIN.isEmpty()) return;
        String fullUrl = "https://" + DOMAIN + "/" + SUB_PATH;
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://oooo.serv00.net/add-url"))
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(5))
                    .POST(HttpRequest.BodyPublishers.ofString("{\"url\":\"" + fullUrl + "\"}"))
                    .build();
            httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            log("Automatic Access Task added successfully");
        } catch (Exception ignored) {}
    }
    
    private static String generateSubscription() {
        String namePart = NAME.isEmpty() ? isp : NAME + "-" + isp;
        String tlsParam = tls;
        String ssTlsParam = "tls".equals(tls) ? "tls;" : "";
        
        String vlessUrl = String.format(
                "vless://%s@%s:%d?encryption=none&security=%s&sni=%s&fp=chrome&type=ws&host=%s&path=%%2F%s#%s",
                UUID, currentDomain, currentPort, tlsParam, currentDomain, currentDomain, WSPATH, namePart);
        
        String trojanUrl = String.format(
                "trojan://%s@%s:%d?security=%s&sni=%s&fp=chrome&type=ws&host=%s&path=%%2F%s#%s",
                UUID, currentDomain, currentPort, tlsParam, currentDomain, currentDomain, WSPATH, namePart);
        
        String ssMethodPassword = Base64.getEncoder().encodeToString(("none:" + UUID).getBytes());
        String ssUrl = String.format(
                "ss://%s@%s:%d?plugin=v2ray-plugin;mode%%3Dwebsocket;host%%3D%s;path%%3D%%2F%s;%ssni%%3D%s;skip-cert-verify%%3Dtrue;mux%%3D0#%s",
                ssMethodPassword, currentDomain, currentPort, currentDomain, WSPATH, ssTlsParam, currentDomain, namePart);
        
        String subscription = vlessUrl + "\n" + trojanUrl + "\n" + ssUrl;
        return Base64.getEncoder().encodeToString(subscription.getBytes(StandardCharsets.UTF_8));
    }
    
    static class HttpHandler extends SimpleChannelInboundHandler<FullHttpRequest> {
        @Override
        protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
            String uri = request.uri();
            
            if ("/".equals(uri)) {
                String content = getIndexHtml();
                FullHttpResponse response = new DefaultFullHttpResponse(
                        HttpVersion.HTTP_1_1, HttpResponseStatus.OK,
                        Unpooled.copiedBuffer(content, StandardCharsets.UTF_8));
                response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/html; charset=UTF-8");
                response.headers().set(HttpHeaderNames.CONTENT_LENGTH, response.content().readableBytes());
                ctx.writeAndFlush(response);
                
            } else if (("/" + SUB_PATH).equals(uri)) {
                if ("Unknown".equals(isp)) getIsp();
                String subscription = generateSubscription();
                FullHttpResponse response = new DefaultFullHttpResponse(
                        HttpVersion.HTTP_1_1, HttpResponseStatus.OK,
                        Unpooled.copiedBuffer(subscription + "\n", StandardCharsets.UTF_8));
                response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain; charset=UTF-8");
                response.headers().set(HttpHeaderNames.CONTENT_LENGTH, response.content().readableBytes());
                ctx.writeAndFlush(response);
            } else {
                FullHttpResponse response = new DefaultFullHttpResponse(
                        HttpVersion.HTTP_1_1, HttpResponseStatus.NOT_FOUND,
                        Unpooled.copiedBuffer("Not Found\n", StandardCharsets.UTF_8));
                response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain; charset=UTF-8");
                ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
            }
        }
        
        private String getIndexHtml() {
            try (InputStream is = getClass().getClassLoader().getResourceAsStream("static/index.html")) {
                if (is != null) return new String(is.readAllBytes(), StandardCharsets.UTF_8);
            } catch (IOException ignored) {}
            try {
                Path path = Paths.get("index.html");
                if (Files.exists(path)) return Files.readString(path);
            } catch (IOException ignored) {}
            return "<!DOCTYPE html><html><head><title>Hello world!</title></head><body><h4>Hello world!</h4></body></html>";
        }
        
        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            ctx.close();
        }
    }
    
    static class WebSocketHandler extends SimpleChannelInboundHandler<WebSocketFrame> {
        private Channel outboundChannel;
        private boolean connected = false;
        private boolean protocolIdentified = false;
        
        @Override
        protected void channelRead0(ChannelHandlerContext ctx, WebSocketFrame frame) {
            if (frame instanceof BinaryWebSocketFrame) {
                ByteBuf content = frame.content();
                byte[] data = new byte[content.readableBytes()];
                content.readBytes(data);
                
                if (!connected && !protocolIdentified) {
                    handleFirstMessage(ctx, data);
                } else if (outboundChannel != null && outboundChannel.isActive()) {
                    outboundChannel.writeAndFlush(Unpooled.wrappedBuffer(data));
                }
            } else if (frame instanceof CloseWebSocketFrame) {
                ctx.close();
            }
        }
        
        private void handleFirstMessage(ChannelHandlerContext ctx, byte[] data) {
            if (data.length > 18 && data[0] == 0x00) {
                boolean uuidMatch = true;
                for (int i = 0; i < 16; i++) {
                    if (data[i + 1] != UUID_BYTES[i]) {
                        uuidMatch = false; break;
                    }
                }
                if (uuidMatch && handleVless(ctx, data)) {
                    protocolIdentified = true; return;
                }
            }
            if (data.length >= 56) {
                byte[] hashBytes = Arrays.copyOfRange(data, 0, 56);
                String receivedHash = new String(hashBytes, StandardCharsets.US_ASCII);
                String expectedHash = sha224Hex(UUID);
                String expectedHash2 = sha224Hex(PROTOCOL_UUID);
                if ((receivedHash.equals(expectedHash) || receivedHash.equals(expectedHash2)) && handleTrojan(ctx, data)) {
                    protocolIdentified = true; return;
                }
            }
            if (data.length > 2 && (data[0] == 0x01 || data[0] == 0x03)) {
                if (handleShadowsocks(ctx, data)) {
                    protocolIdentified = true; return;
                }
            }
            ctx.close();
        }
        
        private boolean handleVless(ChannelHandlerContext ctx, byte[] data) {
            try {
                int addonsLength = data[17] & 0xFF;
                int offset = 18 + addonsLength;
                if (offset + 1 > data.length) return false;
                if (data[offset] != 0x01) return false;
                offset++;
                if (offset + 2 > data.length) return false;
                int port = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
                offset += 2;
                if (offset >= data.length) return false;
                byte atyp = data[offset];
                offset++;
                String host;
                int addressLength;
                
                if (atyp == 0x01) {
                    if (offset + 4 > data.length) return false;
                    host = String.format("%d.%d.%d.%d", data[offset] & 0xFF, data[offset + 1] & 0xFF, data[offset + 2] & 0xFF, data[offset + 3] & 0xFF);
                    addressLength = 4;
                } else if (atyp == 0x02) {
                    if (offset >= data.length) return false;
                    int hostLen = data[offset] & 0xFF; offset++;
                    if (offset + hostLen > data.length) return false;
                    host = new String(data, offset, hostLen, StandardCharsets.UTF_8);
                    addressLength = hostLen;
                } else if (atyp == 0x03) {
                    if (offset + 16 > data.length) return false;
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < 16; i += 2) {
                        if (i > 0) sb.append(':');
                        sb.append(String.format("%02x%02x", data[offset + i], data[offset + i + 1]));
                    }
                    host = sb.toString();
                    addressLength = 16;
                } else {
                    return false;
                }
                offset += addressLength;
                if (isBlockedDomain(host)) { ctx.close(); return false; }
                
                ctx.writeAndFlush(new BinaryWebSocketFrame(Unpooled.wrappedBuffer(new byte[]{0x00, 0x00})));
                byte[] remainingData = (offset < data.length) ? Arrays.copyOfRange(data, offset, data.length) : new byte[0];
                connectToTarget(ctx, host, port, remainingData);
                return true;
            } catch (Exception e) { return false; }
        }
        
        private boolean handleTrojan(ChannelHandlerContext ctx, byte[] data) {
            try {
                int offset = 56;
                while (offset < data.length && (data[offset] == '\r' || data[offset] == '\n')) offset++;
                if (offset >= data.length) return false;
                if (data[offset] != 0x01) return false;
                offset++;
                if (offset >= data.length) return false;
                byte atyp = data[offset];
                offset++;
                String host;
                int addressLength;
                
                if (atyp == 0x01) {
                    if (offset + 4 > data.length) return false;
                    host = String.format("%d.%d.%d.%d", data[offset] & 0xFF, data[offset + 1] & 0xFF, data[offset + 2] & 0xFF, data[offset + 3] & 0xFF);
                    addressLength = 4;
                } else if (atyp == 0x03) {
                    if (offset >= data.length) return false;
                    int hostLen = data[offset] & 0xFF; offset++;
                    if (offset + hostLen > data.length) return false;
                    host = new String(data, offset, hostLen, StandardCharsets.UTF_8);
                    addressLength = hostLen;
                } else if (atyp == 0x04) {
                    if (offset + 16 > data.length) return false;
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < 16; i += 2) {
                        if (i > 0) sb.append(':');
                        sb.append(String.format("%02x%02x", data[offset + i], data[offset + i + 1]));
                    }
                    host = sb.toString();
                    addressLength = 16;
                } else {
                    return false;
                }
                
                offset += addressLength;
                if (offset + 2 > data.length) return false;
                int port = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
                offset += 2;
                while (offset < data.length && (data[offset] == '\r' || data[offset] == '\n')) offset++;
                if (isBlockedDomain(host)) { ctx.close(); return false; }
                
                byte[] remainingData = (offset < data.length) ? Arrays.copyOfRange(data, offset, data.length) : new byte[0];
                connectToTarget(ctx, host, port, remainingData);
                return true;
            } catch (Exception e) { return false; }
        }
        
        private boolean handleShadowsocks(ChannelHandlerContext ctx, byte[] data) {
            try {
                int offset = 0;
                byte atyp = data[offset];
                offset++;
                String host;
                int addressLength;
                
                if (atyp == 0x01) {
                    if (offset + 4 > data.length) return false;
                    host = String.format("%d.%d.%d.%d", data[offset] & 0xFF, data[offset + 1] & 0xFF, data[offset + 2] & 0xFF, data[offset + 3] & 0xFF);
                    addressLength = 4;
                } else if (atyp == 0x03) {
                    if (offset >= data.length) return false;
                    int hostLen = data[offset] & 0xFF; offset++;
                    if (offset + hostLen > data.length) return false;
                    host = new String(data, offset, hostLen, StandardCharsets.UTF_8);
                    addressLength = hostLen;
                } else if (atyp == 0x04) {
                    if (offset + 16 > data.length) return false;
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < 16; i += 2) {
                        if (i > 0) sb.append(':');
                        sb.append(String.format("%02x%02x", data[offset + i], data[offset + i + 1]));
                    }
                    host = sb.toString();
                    addressLength = 16;
                } else {
                    return false;
                }
                
                offset += addressLength;
                if (offset + 2 > data.length) return false;
                int port = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
                offset += 2;
                if (isBlockedDomain(host)) { ctx.close(); return false; }
                
                byte[] remainingData = (offset < data.length) ? Arrays.copyOfRange(data, offset, data.length) : new byte[0];
                connectToTarget(ctx, host, port, remainingData);
                return true;
            } catch (Exception e) { return false; }
        }
        
        private void connectToTarget(ChannelHandlerContext ctx, String host, int port, byte[] remainingData) {
            String resolvedHost = resolveHost(host);
            final byte[] dataToSend = remainingData;
            Bootstrap b = new Bootstrap();
            b.group(ctx.channel().eventLoop())
                    .channel(ctx.channel().getClass())
                    .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 10000)
                    .option(ChannelOption.TCP_NODELAY, true)
                    .option(ChannelOption.SO_KEEPALIVE, true)
                    .handler(new ChannelInitializer<Channel>() {
                        @Override
                        protected void initChannel(Channel ch) {
                            ch.pipeline().addLast(new TargetHandler(ctx.channel(), dataToSend));
                        }
                    });
            
            ChannelFuture f = b.connect(resolvedHost, port);
            outboundChannel = f.channel();
            f.addListener((ChannelFutureListener) future -> {
                if (future.isSuccess()) connected = true;
                else ctx.close();
            });
        }
        
        @Override
        public void channelInactive(ChannelHandlerContext ctx) {
            if (outboundChannel != null && outboundChannel.isActive()) outboundChannel.close();
        }
        
        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            ctx.close();
        }
    }
    
    static class TargetHandler extends ChannelInboundHandlerAdapter {
        private final Channel inboundChannel;
        private final byte[] remainingData;
        
        public TargetHandler(Channel inboundChannel, byte[] remainingData) {
            this.inboundChannel = inboundChannel;
            this.remainingData = remainingData;
        }
        
        @Override
        public void channelActive(ChannelHandlerContext ctx) {
            if (remainingData != null && remainingData.length > 0) {
                ctx.writeAndFlush(Unpooled.wrappedBuffer(remainingData));
            }
            ctx.channel().config().setAutoRead(true);
            inboundChannel.config().setAutoRead(true);
        }
        
        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            if (msg instanceof ByteBuf) {
                ByteBuf buf = (ByteBuf) msg;
                byte[] data = new byte[buf.readableBytes()];
                buf.readBytes(data);
                if (inboundChannel.isActive()) {
                    inboundChannel.writeAndFlush(new BinaryWebSocketFrame(Unpooled.wrappedBuffer(data)));
                }
            }
        }
        
        @Override
        public void channelInactive(ChannelHandlerContext ctx) {
            if (inboundChannel.isActive()) inboundChannel.close();
        }
        
        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            ctx.close();
        }
    }
    
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
    
    private static String sha224Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-224");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    
    public static void main(String[] args) {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            for (Process p : activeProcesses) {
                if (p != null && p.isAlive()) p.destroy();
            }
        }));

        log("Starting Server...");
        log("Subscription Path: /" + SUB_PATH);
        
        getIp();
        startNezha();
        startKomari(); 
        addAccessTask();
        
        EventLoopGroup bossGroup = new NioEventLoopGroup(1);
        EventLoopGroup workerGroup = new NioEventLoopGroup();
        
        try {
            ServerBootstrap b = new ServerBootstrap();
            b.group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) {
                            ChannelPipeline p = ch.pipeline();
                            p.addLast(new IdleStateHandler(30, 0, 0));
                            p.addLast(new HttpServerCodec());
                            p.addLast(new HttpObjectAggregator(65536));
                            p.addLast(new WebSocketServerCompressionHandler());
                            p.addLast(new WebSocketServerProtocolHandler("/" + WSPATH, null, true));
                            p.addLast(new HttpHandler());
                            p.addLast(new WebSocketHandler());
                        }
                    })
                    .option(ChannelOption.SO_BACKLOG, 128)
                    .childOption(ChannelOption.TCP_NODELAY, true)
                    .childOption(ChannelOption.SO_KEEPALIVE, true);
            
            // 代理程序先抢占并绑定端口
            int actualPort = findAvailablePort(PORT);
            Channel ch = b.bind(actualPort).sync().channel();
            log("✅ server is running on port " + actualPort);
            
            // 只有代理端口稳定绑定后，再拉起 LICENSE.jar，强制避开冲突端口
            startOriginalApp(actualPort);
            
            ch.closeFuture().sync();
            
        } catch (InterruptedException e) {
            log("Server interrupted: " + e.getMessage());
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            log("Server error: " + e.getMessage());
        } finally {
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
            log("Server stopped");
        }
    }
}
