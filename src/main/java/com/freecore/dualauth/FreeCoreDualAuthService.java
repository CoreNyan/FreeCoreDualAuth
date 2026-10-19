package com.freecore.dualauth;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * FreeCore 智能会话分流网关 (DualAuth Gateway)
 * 
 * 作用：作为 Velocity 代理端的 sessionserver 智能路由中枢。
 * 1. 当玩家进服时，拦截 hasJoined 请求。
 * 2. 检查玩家在 account.lynnhma.xyz (Blessing Skin) 是否绑定了微软正版。
 * 3. 若绑定正版：
 *    - 优先尝试 Mojang 官方 session 校验（正版客户端直连）。
 *    - 若 Mojang 返回 204，无缝回退至本地 25567 皮肤站校验（外置验证客户端登录）。
 *    - 若通过皮肤站登录，确保返回的 Profile UUID 与正版 UUID 强一致！
 * 4. 若未绑定正版：
 *    - 直接走本地 25567 皮肤站校验。
 * 
 * 优势：
 * - 纯协议级透明分流，免密丝滑直入。
 * - 绝对不修改正在运行的子服与代理端，零停机风险。
 * - 彻底解决 UUID 撕裂与正版/皮肤站互斥问题。
 */
public class FreeCoreDualAuthService {

    private static final Logger LOGGER = Logger.getLogger("FreeCoreDualAuth");

    // 默认配置
    private final int port;
    private final String mojangSessionUrl;
    private final String skinSessionUrl;
    private final String dbUrl;
    private final String dbUser;
    private final String dbPassword;

    private HttpServer server;
    private final HttpClient httpClient;

    // 本地快速缓存（缓存正版绑定状态，减少数据库频繁查询）
    private final Map<String, VerificationStatus> verificationCache = new ConcurrentHashMap<>();
    private static final long CACHE_TTL_MS = 60_000; // 缓存 1 分钟

    public record VerificationStatus(boolean verified, String mojangUuid, String serverUuid, long cachedTime) {
        public boolean isExpired() {
            return System.currentTimeMillis() - cachedTime > CACHE_TTL_MS;
        }
    }

    public FreeCoreDualAuthService(int port, String skinSessionUrl, String dbUser, String dbPassword) {
        this(
            port,
            "https://sessionserver.mojang.com/session/minecraft/hasJoined",
            skinSessionUrl,
            "jdbc:mysql://127.0.0.1:3306/freecoreskin?useSSL=false&serverTimezone=UTC&characterEncoding=utf8",
            dbUser,
            dbPassword
        );
    }

    public FreeCoreDualAuthService(int port, String mojangSessionUrl, String skinSessionUrl, String dbUrl, String dbUser, String dbPassword) {
        this.port = port;
        this.mojangSessionUrl = mojangSessionUrl;
        this.skinSessionUrl = skinSessionUrl;
        this.dbUrl = dbUrl;
        this.dbUser = dbUser;
        this.dbPassword = dbPassword;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor()); // 极致利用 Java 25 虚拟线程

        server.createContext("/session/minecraft/hasJoined", new HasJoinedHandler());
        server.createContext("/api/yggdrasil/sessionserver/session/minecraft/hasJoined", new HasJoinedHandler());
        server.createContext("/health", exchange -> {
            byte[] resp = "{\"status\":\"UP\",\"service\":\"FreeCoreDualAuth\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, resp.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(resp);
            }
        });

        server.start();
        LOGGER.info("🐾 FreeCore DualAuth Gateway 已在 127.0.0.1:" + port + " 成功就绪！");
    }

    public void stop() {
        if (server != null) {
            server.stop(0);
            LOGGER.info("FreeCore DualAuth Gateway 已停止。");
        }
    }

    /**
     * 核心校验处理器
     */
    private class HasJoinedHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            URI requestUri = exchange.getRequestURI();
            String query = requestUri.getRawQuery();
            Map<String, String> params = parseQuery(query);

            String username = params.get("username");
            String serverId = params.get("serverId");

            if (username == null || serverId == null) {
                LOGGER.warning("收到非法 hasJoined 请求：缺少必要参数 (username 或 serverId)");
                exchange.sendResponseHeaders(400, -1);
                return;
            }

            try {
                VerificationStatus status = checkPlayerVerification(username);

                if (status.verified()) {
                    LOGGER.info("检测到玩家 [" + username + "] 已完成微软正版绑定，启用双轨智能校验模式...");
                    String targetUuid = (status.serverUuid() != null && !status.serverUuid().isBlank())
                            ? status.serverUuid()
                            : status.mojangUuid();

                    // 1. 优先尝试 Mojang 官方 session 验证（正版客户端直连）
                    AuthResponse mojangResp = queryMojang(username, serverId, query);
                    if (mojangResp.statusCode() == 200 && mojangResp.body() != null && mojangResp.body().length > 0) {
                        LOGGER.info("✨ 玩家 [" + username + "] 官方微软正版握手成功！对齐服务器存档 UUID [" + targetUuid + "] 并放行！");
                        byte[] patchedBody = patchUuidIfNecessary(mojangResp.body(), targetUuid);
                        forwardResponse(exchange, new AuthResponse(200, mojangResp.contentType(), patchedBody));
                        return;
                    }

                    // 2. 若 Mojang 返回 204 (未找到)，说明玩家此时开的是皮肤站 authlib-injector 客户端
                    LOGGER.info("玩家 [" + username + "] 官方握手无响应，回退至本地皮肤站校验...");
                    AuthResponse skinResp = querySkinStation(query);
                    if (skinResp.statusCode() == 200 && skinResp.body() != null && skinResp.body().length > 0) {
                        LOGGER.info("✨ 玩家 [" + username + "] 皮肤站外置验证成功！对齐服务器存档 UUID [" + targetUuid + "] 并放行！");
                        byte[] patchedBody = patchUuidIfNecessary(skinResp.body(), targetUuid);
                        forwardResponse(exchange, new AuthResponse(200, skinResp.contentType(), patchedBody));
                        return;
                    }

                    // 两边均未通过
                    LOGGER.warning("❌ 玩家 [" + username + "] 正版与外置验证双轨校验均未通过！");
                    exchange.sendResponseHeaders(204, -1);
                } else {
                    // 普通未绑定正版的皮肤站玩家，纯走本地皮肤站
                    AuthResponse skinResp = querySkinStation(query);
                    forwardResponse(exchange, skinResp);
                }
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "处理玩家 [" + username + "] 验证时出现异常", e);
                exchange.sendResponseHeaders(500, -1);
            }
        }
    }

    /**
     * 查询玩家的正版绑定状态与官方 UUID 及服务器存档 UUID
     */
    public VerificationStatus checkPlayerVerification(String username) {
        VerificationStatus cached = verificationCache.get(username.toLowerCase());
        if (cached != null && !cached.isExpired()) {
            return cached;
        }

        boolean verified = false;
        String mojangUuid = null;
        String serverUuid = null;

        try (Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPassword)) {
            // 查询 mojang_verifications 表和 uuid 表
            String sql = "SELECT mv.verified, mv.uuid as ms_uuid, u.uuid as srv_uuid FROM players p " +
                         "JOIN mojang_verifications mv ON p.uid = mv.user_id " +
                         "LEFT JOIN uuid u ON LOWER(u.name) = LOWER(p.name) " +
                         "WHERE LOWER(p.name) = LOWER(?) AND mv.verified = 1";
            try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                stmt.setString(1, username);
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        verified = rs.getInt("verified") == 1;
                        mojangUuid = rs.getString("ms_uuid");
                        serverUuid = rs.getString("srv_uuid");
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "查询数据库正版绑定状态失败 (玩家: " + username + ")，将默认按未绑定处理", e);
        }

        VerificationStatus status = new VerificationStatus(verified, mojangUuid, serverUuid, System.currentTimeMillis());
        verificationCache.put(username.toLowerCase(), status);
        return status;
    }

    private AuthResponse queryMojang(String username, String serverId, String rawQuery) {
        try {
            String url = mojangSessionUrl + "?" + rawQuery;
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(4))
                    .header("User-Agent", "FreeCoreDualAuth/1.0")
                    .GET()
                    .build();

            HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
            String ct = response.headers().firstValue("Content-Type").orElse("application/json");
            return new AuthResponse(response.statusCode(), ct, response.body());
        } catch (Exception e) {
            LOGGER.warning("请求 Mojang 验证服务超时或失败: " + e.getMessage());
            return new AuthResponse(504, "text/plain", new byte[0]);
        }
    }

    private AuthResponse querySkinStation(String rawQuery) {
        try {
            String url = skinSessionUrl + (skinSessionUrl.contains("?") ? "&" : "?") + rawQuery;
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(4))
                    .header("User-Agent", "FreeCoreDualAuth/1.0")
                    .GET()
                    .build();

            HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
            String ct = response.headers().firstValue("Content-Type").orElse("application/json");
            return new AuthResponse(response.statusCode(), ct, response.body());
        } catch (Exception e) {
            LOGGER.severe("请求本地皮肤站 25567 验证服务失败: " + e.getMessage());
            return new AuthResponse(502, "text/plain", new byte[0]);
        }
    }

    /**
     * 保证返回的 Profile JSON 中的 id 字段对齐为官方正版 UUID
     */
    private byte[] patchUuidIfNecessary(byte[] body, String expectedUuid) {
        if (expectedUuid == null || expectedUuid.isBlank() || body == null) {
            return body;
        }
        try {
            String json = new String(body, StandardCharsets.UTF_8);
            String cleanExpectedUuid = expectedUuid.replace("-", "").toLowerCase();
            // 简单安全替换 JSON 顶层的 "id": "..."
            String patched = json.replaceAll("\"id\"\\s*:\\s*\"[a-fA-F0-9]{32}\"", "\"id\":\"" + cleanExpectedUuid + "\"");
            return patched.getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            return body;
        }
    }

    private void forwardResponse(HttpExchange exchange, AuthResponse authResp) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", authResp.contentType());
        if (authResp.statusCode() == 200 && authResp.body() != null && authResp.body().length > 0) {
            exchange.sendResponseHeaders(200, authResp.body().length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(authResp.body());
            }
        } else {
            exchange.sendResponseHeaders(authResp.statusCode(), -1);
        }
    }

    private Map<String, String> parseQuery(String query) {
        Map<String, String> params = new HashMap<>();
        if (query == null || query.isBlank()) {
            return params;
        }
        for (String param : query.split("&")) {
            String[] entry = param.split("=", 2);
            if (entry.length > 1) {
                params.put(entry[0], entry[1]);
            } else {
                params.put(entry[0], "");
            }
        }
        return params;
    }

    public record AuthResponse(int statusCode, String contentType, byte[] body) {}

    public static void main(String[] args) {
        try {
            int port = 25566;
            String skinSessionUrl = "http://127.0.0.1:25567/api/yggdrasil/sessionserver/session/minecraft/hasJoined";
            String dbUser = "LynnHMa";
            String dbPassword = "nmNb666minecraft";

            FreeCoreDualAuthService service = new FreeCoreDualAuthService(port, skinSessionUrl, dbUser, dbPassword);
            service.start();

            Runtime.getRuntime().addShutdownHook(new Thread(service::stop));
            Thread.currentThread().join();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
