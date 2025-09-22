/*
* GNU GENERAL PUBLIC LICENSE
* Version 3, 29 June 2007

* Copyright (C) 2025 Smarttfoxx

* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, 
* or any later version.

* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.

* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <https://www.gnu.org/licenses/>.

* This program comes with ABSOLUTELY NO WARRANTY; This is free software, 
* and you are welcome to redistribute it under certain conditions.
*/

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>
#include <functional>
#include "../utilities/output_formats.h"
#include "../distributed/scan_coordinator.h"

// Note: Enterprise authentication components removed - using simple auth only

/**
 * Web-based management interface for Hugin network scanner
 */

/**
 * HTTP request/response structures
 */
struct HTTPRequest {
    std::string method;
    std::string path;
    std::string version;
    std::unordered_map<std::string, std::string> headers;
    std::unordered_map<std::string, std::string> query_params;
    std::string body;
    std::string client_ip;
};

struct HTTPResponse {
    int status_code;
    std::string status_message;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
    
    HTTPResponse(int code = 200, const std::string& message = "OK") 
        : status_code(code), status_message(message) {
        headers["Content-Type"] = "text/html; charset=utf-8";
        headers["Server"] = "Hugin-Web/2.0";
    }
};

/**
 * WebSocket connection for real-time updates
 */
class WebSocketConnection {
private:
    int socket_fd_;
    std::string connection_id_;
    bool authenticated_;
    std::atomic<bool> active_;
    std::thread message_thread_;
    
public:
    WebSocketConnection(int socket_fd, const std::string& connection_id);
    ~WebSocketConnection();
    
    bool SendMessage(const std::string& message);
    bool SendJSON(const std::string& json_data);
    void StartMessageLoop();
    void Close();
    
    bool IsActive() const { return active_; }
    const std::string& GetConnectionId() const { return connection_id_; }
    bool IsAuthenticated() const { return authenticated_; }
    void SetAuthenticated(bool auth) { authenticated_ = auth; }
    
private:
    void MessageLoop();
    std::string ReceiveMessage();
    bool SendFrame(const std::string& data, int opcode = 1);
};

/**
 * Session management for web interface
 */
class SessionManager {
private:
    struct Session {
        std::string session_id;
        std::string user_id;
        std::chrono::system_clock::time_point created_at;
        std::chrono::system_clock::time_point last_access;
        std::unordered_map<std::string, std::string> data;
        bool authenticated;
    };
    
    std::unordered_map<std::string, Session> sessions_;
    std::mutex sessions_mutex_;
    int session_timeout_minutes_;
    
public:
    SessionManager(int timeout_minutes = 60);
    
    std::string CreateSession(const std::string& user_id = "");
    bool ValidateSession(const std::string& session_id);
    bool AuthenticateSession(const std::string& session_id, const std::string& user_id);
    void DestroySession(const std::string& session_id);
    void CleanupExpiredSessions();
    
    bool SetSessionData(const std::string& session_id, const std::string& key, const std::string& value);
    std::string GetSessionData(const std::string& session_id, const std::string& key);
    
private:
    std::string GenerateSessionId();
    bool IsSessionExpired(const Session& session);
};

/**
 * Authentication and authorization system
 */
class WebAuthManager {
public:
    enum class UserRole {
        VIEWER,      // Read-only access
        OPERATOR,    // Can run scans
        ADMIN        // Full access including configuration
    };
    
private:
    struct User {
        std::string user_id;
        std::string username;
        std::string password_hash;
        std::string email;
        UserRole role;
        bool active;
        std::chrono::system_clock::time_point created_at;
        std::chrono::system_clock::time_point last_login;
        std::vector<std::string> permissions;
    };
    
    std::unordered_map<std::string, User> users_;
    std::string users_file_;
    std::mutex users_mutex_;
    
public:
    WebAuthManager(const std::string& users_file = "users.json");
    
    // User management
    bool CreateUser(const std::string& username, const std::string& password, 
                   const std::string& email, UserRole role);
    bool AuthenticateUser(const std::string& username, const std::string& password);
    bool ChangePassword(const std::string& username, const std::string& old_password, 
                       const std::string& new_password);
    bool DeactivateUser(const std::string& username);
    
    // Authorization
    bool HasPermission(const std::string& username, const std::string& permission);
    UserRole GetUserRole(const std::string& username);
    std::vector<std::string> GetUserPermissions(const std::string& username);
    
    // Session integration
    bool AuthorizeRequest(const HTTPRequest& request, const std::string& required_permission);
    
private:
    bool LoadUsers();
    bool SaveUsers();
    std::string HashPassword(const std::string& password);
    bool VerifyPassword(const std::string& password, const std::string& hash);
    std::string GenerateUserId();
};

/**
 * REST API endpoints for programmatic access
 */
class HuginRESTAPI {
private:
    std::shared_ptr<DistributedScanManager> scan_manager_;
    std::shared_ptr<WebAuthManager> auth_manager_;
    
public:
    HuginRESTAPI(std::shared_ptr<DistributedScanManager> scan_manager,
                 std::shared_ptr<WebAuthManager> auth_manager);
    
    // Scan management endpoints
    HTTPResponse StartScan(const HTTPRequest& request);
    HTTPResponse GetScanStatus(const HTTPRequest& request);
    HTTPResponse GetScanResults(const HTTPRequest& request);
    HTTPResponse CancelScan(const HTTPRequest& request);
    HTTPResponse ListScans(const HTTPRequest& request);
    
    // Node management endpoints
    HTTPResponse GetNodes(const HTTPRequest& request);
    HTTPResponse GetNodeStatus(const HTTPRequest& request);
    HTTPResponse RegisterNode(const HTTPRequest& request);
    HTTPResponse DeregisterNode(const HTTPRequest& request);
    
    // System endpoints
    HTTPResponse GetSystemStatus(const HTTPRequest& request);
    HTTPResponse GetStatistics(const HTTPRequest& request);
    HTTPResponse GetConfiguration(const HTTPRequest& request);
    HTTPResponse UpdateConfiguration(const HTTPRequest& request);
    
    // Export endpoints
    HTTPResponse ExportResults(const HTTPRequest& request);
    HTTPResponse GenerateReport(const HTTPRequest& request);
    
    // Authentication endpoints
    HTTPResponse Login(const HTTPRequest& request);
    HTTPResponse Logout(const HTTPRequest& request);
    HTTPResponse RefreshToken(const HTTPRequest& request);
    
private:
    std::string ExtractPathParameter(const std::string& path, const std::string& param_name);
    std::unordered_map<std::string, std::string> ParseJSONBody(const std::string& body);
    HTTPResponse CreateJSONResponse(const std::string& json_data, int status_code = 200);
    HTTPResponse CreateErrorResponse(const std::string& error_message, int status_code = 400);
    bool ValidateAPIKey(const HTTPRequest& request);
};

/**
 * Main web server implementation
 */
class HuginWebServer {
private:
    int port_;
    std::atomic<bool> running_;
    std::thread server_thread_;
    
    std::shared_ptr<SessionManager> session_manager_;
    std::shared_ptr<WebAuthManager> auth_manager_;
    std::shared_ptr<HuginRESTAPI> rest_api_;
    std::shared_ptr<DistributedScanManager> scan_manager_;
    
    std::vector<std::unique_ptr<WebSocketConnection>> websocket_connections_;
    std::mutex connections_mutex_;
    
    std::string static_files_path_;
    std::string templates_path_;
    
public:
    HuginWebServer(int port = 8080, const std::string& static_path = "web/static");
    ~HuginWebServer();
    
    // Server lifecycle
    bool Start();
    void Stop();
    bool IsRunning() const;
    
    // Configuration
    void SetScanManager(std::shared_ptr<DistributedScanManager> manager);
    void SetStaticFilesPath(const std::string& path);
    void SetTemplatesPath(const std::string& path);
    
    // WebSocket management
    void BroadcastMessage(const std::string& message);
    void SendToConnection(const std::string& connection_id, const std::string& message);
    void BroadcastScanUpdate(const std::string& scan_id, const std::string& status);
    
private:
    void ServerLoop();
    void HandleConnection(int client_socket);
    HTTPRequest ParseHTTPRequest(const std::string& request_data);
    std::string FormatHTTPResponse(const HTTPResponse& response);
    
    // Route handlers
    HTTPResponse HandleStaticFile(const HTTPRequest& request);
    HTTPResponse HandleDashboard(const HTTPRequest& request);
    HTTPResponse HandleScanPage(const HTTPRequest& request);
    HTTPResponse HandleResultsPage(const HTTPRequest& request);
    HTTPResponse HandleNodesPage(const HTTPRequest& request);
    HTTPResponse HandleSettingsPage(const HTTPRequest& request);
    HTTPResponse HandleLoginPage(const HTTPRequest& request);
    
    // WebSocket handling
    bool HandleWebSocketUpgrade(int client_socket, const HTTPRequest& request);
    void HandleWebSocketMessage(WebSocketConnection* connection, const std::string& message);
    
    // Template rendering
    std::string RenderTemplate(const std::string& template_name, 
                              const std::unordered_map<std::string, std::string>& variables);
    std::string LoadTemplate(const std::string& template_name);
    
    // Utility functions
    std::string GetMimeType(const std::string& file_extension);
    std::string URLDecode(const std::string& encoded);
    std::unordered_map<std::string, std::string> ParseQueryString(const std::string& query);
};

/**
 * Real-time dashboard for monitoring scans
 */
class ScanDashboard {
private:
    std::shared_ptr<DistributedScanManager> scan_manager_;
    std::shared_ptr<HuginWebServer> web_server_;
    
    std::thread update_thread_;
    std::atomic<bool> running_;
    int update_interval_seconds_;
    
public:
    ScanDashboard(std::shared_ptr<DistributedScanManager> scan_manager,
                  std::shared_ptr<HuginWebServer> web_server);
    ~ScanDashboard();
    
    void Start();
    void Stop();
    
    // Dashboard data generation
    std::string GenerateDashboardData();
    std::string GenerateNodeStatusData();
    std::string GenerateScanProgressData();
    std::string GeneratePerformanceMetrics();
    
private:
    void UpdateLoop();
    void BroadcastUpdate(const std::string& update_type, const std::string& data);
};

/**
 * Configuration management for web interface
 */
class WebConfiguration {
private:
    std::string config_file_;
    std::unordered_map<std::string, std::string> settings_;
    std::mutex config_mutex_;
    
public:
    WebConfiguration(const std::string& config_file = "web_config.json");
    
    bool LoadConfiguration();
    bool SaveConfiguration();
    
    std::string GetSetting(const std::string& key, const std::string& default_value = "");
    void SetSetting(const std::string& key, const std::string& value);
    
    // Specific configuration getters/setters
    int GetPort() const;
    void SetPort(int port);
    
    std::string GetStaticPath() const;
    void SetStaticPath(const std::string& path);
    
    bool IsSSLEnabled() const;
    void EnableSSL(const std::string& cert_file, const std::string& key_file);
    void DisableSSL();
    
    int GetMaxConnections() const;
    void SetMaxConnections(int max_connections);
    
    std::vector<std::string> GetAllowedIPs() const;
    void SetAllowedIPs(const std::vector<std::string>& ips);
};

/**
 * High-level web interface manager
 */
class HuginWebManager {
private:
    std::unique_ptr<HuginWebServer> web_server_;
    std::unique_ptr<ScanDashboard> dashboard_;
    std::unique_ptr<WebConfiguration> config_;
    std::shared_ptr<DistributedScanManager> scan_manager_;
    
public:
    HuginWebManager();
    ~HuginWebManager();
    
    bool Initialize(const std::string& config_file = "");
    bool Start(int port = 8080);
    void Stop();
    
    void SetScanManager(std::shared_ptr<DistributedScanManager> manager);
    
    // Web interface control
    void EnableDashboard();
    void DisableDashboard();
    void EnableAuthentication();
    void DisableAuthentication();
    
    // SSL/TLS configuration
    bool EnableSSL(const std::string& cert_file, const std::string& key_file);
    void DisableSSL();
    
    // Access control
    void SetAllowedIPs(const std::vector<std::string>& ips);
    void EnableIPWhitelist(bool enable);
    
    // Monitoring
    void GenerateAccessLog();
    void GenerateUsageReport();
};

// Global web interface manager
extern std::unique_ptr<HuginWebManager> web_manager;
