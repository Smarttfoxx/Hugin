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
#include <chrono>
#include <functional>

/**
 * Enterprise authentication and authorization system for Hugin
 */

enum class AuthProvider {
    LOCAL,           // Local user database
    LDAP,           // LDAP/Active Directory
    SAML,           // SAML 2.0 SSO
    OAUTH2,         // OAuth 2.0 / OpenID Connect
    RADIUS,         // RADIUS authentication
    KERBEROS,       // Kerberos authentication
    CERTIFICATE     // X.509 certificate authentication
};

enum class Permission {
    SCAN_READ,              // View scan results
    SCAN_EXECUTE,           // Execute scans
    SCAN_MANAGE,            // Manage scan configurations
    NODE_VIEW,              // View node status
    NODE_MANAGE,            // Manage scanning nodes
    SYSTEM_CONFIG,          // System configuration
    USER_MANAGE,            // User management
    AUDIT_VIEW,             // View audit logs
    REPORT_GENERATE,        // Generate reports
    API_ACCESS,             // API access
    ADMIN_FULL             // Full administrative access
};

/**
 * User identity and profile information
 */
struct UserIdentity {
    std::string user_id;
    std::string username;
    std::string email;
    std::string full_name;
    std::string department;
    std::string organization;
    std::vector<std::string> groups;
    std::vector<Permission> permissions;
    std::unordered_map<std::string, std::string> attributes;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point last_login;
    bool active;
};

/**
 * Authentication token for session management
 */
struct AuthToken {
    std::string token_id;
    std::string user_id;
    std::string token_value;
    std::chrono::system_clock::time_point issued_at;
    std::chrono::system_clock::time_point expires_at;
    std::string issuer;
    std::vector<Permission> permissions;
    std::unordered_map<std::string, std::string> claims;
    bool revoked;
};

/**
 * Base authentication provider interface
 */
class AuthenticationProvider {
public:
    virtual ~AuthenticationProvider() = default;
    
    virtual bool Initialize(const std::unordered_map<std::string, std::string>& config) = 0;
    virtual bool Authenticate(const std::string& username, const std::string& credential) = 0;
    virtual UserIdentity GetUserIdentity(const std::string& username) = 0;
    virtual std::vector<Permission> GetUserPermissions(const std::string& username) = 0;
    virtual bool ValidateToken(const std::string& token) = 0;
    virtual AuthProvider GetProviderType() const = 0;
    virtual std::string GetProviderName() const = 0;
};

/**
 * Local database authentication provider
 */
class LocalAuthProvider : public AuthenticationProvider {
private:
    std::string database_file_;
    std::unordered_map<std::string, UserIdentity> users_;
    std::unordered_map<std::string, std::string> password_hashes_;
    
public:
    LocalAuthProvider();
    
    bool Initialize(const std::unordered_map<std::string, std::string>& config) override;
    bool Authenticate(const std::string& username, const std::string& credential) override;
    UserIdentity GetUserIdentity(const std::string& username) override;
    std::vector<Permission> GetUserPermissions(const std::string& username) override;
    bool ValidateToken(const std::string& token) override;
    AuthProvider GetProviderType() const override { return AuthProvider::LOCAL; }
    std::string GetProviderName() const override { return "Local Database"; }
    
    // Local user management
    bool CreateUser(const UserIdentity& user, const std::string& password);
    bool UpdateUser(const UserIdentity& user);
    bool DeleteUser(const std::string& username);
    bool ChangePassword(const std::string& username, const std::string& new_password);
    
private:
    bool LoadUsers();
    bool SaveUsers();
    std::string HashPassword(const std::string& password);
    bool VerifyPassword(const std::string& password, const std::string& hash);
};

/**
 * LDAP/Active Directory authentication provider
 */
class LDAPAuthProvider : public AuthenticationProvider {
private:
    std::string ldap_server_;
    int ldap_port_;
    std::string bind_dn_;
    std::string bind_password_;
    std::string base_dn_;
    std::string user_filter_;
    std::string group_filter_;
    bool use_ssl_;
    
public:
    LDAPAuthProvider();
    
    bool Initialize(const std::unordered_map<std::string, std::string>& config) override;
    bool Authenticate(const std::string& username, const std::string& credential) override;
    UserIdentity GetUserIdentity(const std::string& username) override;
    std::vector<Permission> GetUserPermissions(const std::string& username) override;
    bool ValidateToken(const std::string& token) override;
    AuthProvider GetProviderType() const override { return AuthProvider::LDAP; }
    std::string GetProviderName() const override { return "LDAP/Active Directory"; }
    
private:
    bool ConnectToLDAP();
    std::vector<std::string> GetUserGroups(const std::string& username);
    std::vector<Permission> MapGroupsToPermissions(const std::vector<std::string>& groups);
};

/**
 * SAML 2.0 SSO authentication provider
 */
class SAMLAuthProvider : public AuthenticationProvider {
private:
    std::string idp_metadata_url_;
    std::string sp_entity_id_;
    std::string sp_certificate_;
    std::string sp_private_key_;
    std::string sso_url_;
    std::string slo_url_;
    
public:
    SAMLAuthProvider();
    
    bool Initialize(const std::unordered_map<std::string, std::string>& config) override;
    bool Authenticate(const std::string& username, const std::string& credential) override;
    UserIdentity GetUserIdentity(const std::string& username) override;
    std::vector<Permission> GetUserPermissions(const std::string& username) override;
    bool ValidateToken(const std::string& token) override;
    AuthProvider GetProviderType() const override { return AuthProvider::SAML; }
    std::string GetProviderName() const override { return "SAML 2.0 SSO"; }
    
    // SAML-specific methods
    std::string GenerateAuthRequest();
    bool ProcessSAMLResponse(const std::string& saml_response);
    std::string GetSSORedirectURL();
    
private:
    bool LoadIDPMetadata();
    bool ValidateSAMLAssertion(const std::string& assertion);
    UserIdentity ExtractUserFromAssertion(const std::string& assertion);
};

/**
 * OAuth 2.0 / OpenID Connect authentication provider
 */
class OAuth2AuthProvider : public AuthenticationProvider {
private:
    std::string client_id_;
    std::string client_secret_;
    std::string authorization_endpoint_;
    std::string token_endpoint_;
    std::string userinfo_endpoint_;
    std::string redirect_uri_;
    std::vector<std::string> scopes_;
    
public:
    OAuth2AuthProvider();
    
    bool Initialize(const std::unordered_map<std::string, std::string>& config) override;
    bool Authenticate(const std::string& username, const std::string& credential) override;
    UserIdentity GetUserIdentity(const std::string& username) override;
    std::vector<Permission> GetUserPermissions(const std::string& username) override;
    bool ValidateToken(const std::string& token) override;
    AuthProvider GetProviderType() const override { return AuthProvider::OAUTH2; }
    std::string GetProviderName() const override { return "OAuth 2.0 / OpenID Connect"; }
    
    // OAuth2-specific methods
    std::string GetAuthorizationURL(const std::string& state);
    std::string ExchangeCodeForToken(const std::string& authorization_code);
    UserIdentity GetUserInfoFromToken(const std::string& access_token);
    
private:
    std::string GenerateState();
    bool ValidateState(const std::string& state);
    std::string MakeHTTPRequest(const std::string& url, const std::string& method, 
                               const std::unordered_map<std::string, std::string>& headers,
                               const std::string& body = "");
};

/**
 * Multi-factor authentication support
 */
class MFAProvider {
public:
    enum class MFAType {
        TOTP,           // Time-based One-Time Password
        SMS,            // SMS verification
        EMAIL,          // Email verification
        HARDWARE_TOKEN, // Hardware security key
        PUSH            // Push notification
    };
    
private:
    struct MFAConfig {
        MFAType type;
        std::string secret_key;
        std::string phone_number;
        std::string email_address;
        bool enabled;
        std::chrono::system_clock::time_point last_used;
    };
    
    std::unordered_map<std::string, std::vector<MFAConfig>> user_mfa_configs_;
    
public:
    MFAProvider();
    
    // MFA setup
    bool SetupTOTP(const std::string& user_id, const std::string& secret_key);
    bool SetupSMS(const std::string& user_id, const std::string& phone_number);
    bool SetupEmail(const std::string& user_id, const std::string& email_address);
    
    // MFA verification
    bool VerifyTOTP(const std::string& user_id, const std::string& code);
    bool VerifySMS(const std::string& user_id, const std::string& code);
    bool VerifyEmail(const std::string& user_id, const std::string& code);
    
    // MFA management
    bool EnableMFA(const std::string& user_id, MFAType type);
    bool DisableMFA(const std::string& user_id, MFAType type);
    std::vector<MFAType> GetEnabledMFATypes(const std::string& user_id);
    
    // Code generation and sending
    std::string GenerateTOTPSecret();
    bool SendSMSCode(const std::string& phone_number, const std::string& code);
    bool SendEmailCode(const std::string& email_address, const std::string& code);
    
private:
    std::string GenerateRandomCode(int length = 6);
    bool ValidateCodeTiming(const std::chrono::system_clock::time_point& last_used);
};

/**
 * Role-based access control (RBAC) system
 */
class RBACManager {
public:
    struct Role {
        std::string role_id;
        std::string role_name;
        std::string description;
        std::vector<Permission> permissions;
        std::vector<std::string> parent_roles;
        bool active;
    };
    
private:
    std::unordered_map<std::string, Role> roles_;
    std::unordered_map<std::string, std::vector<std::string>> user_roles_;
    
public:
    RBACManager();
    
    // Role management
    bool CreateRole(const Role& role);
    bool UpdateRole(const Role& role);
    bool DeleteRole(const std::string& role_id);
    Role GetRole(const std::string& role_id);
    std::vector<Role> GetAllRoles();
    
    // User-role assignment
    bool AssignRoleToUser(const std::string& user_id, const std::string& role_id);
    bool RemoveRoleFromUser(const std::string& user_id, const std::string& role_id);
    std::vector<std::string> GetUserRoles(const std::string& user_id);
    
    // Permission checking
    bool UserHasPermission(const std::string& user_id, Permission permission);
    std::vector<Permission> GetUserPermissions(const std::string& user_id);
    
    // Role hierarchy
    std::vector<Permission> GetEffectivePermissions(const std::string& role_id);
    bool IsRoleHierarchyValid();
    
private:
    void LoadDefaultRoles();
    std::vector<Permission> ResolveRolePermissions(const std::string& role_id, 
                                                  std::vector<std::string>& visited);
};

/**
 * Audit logging for security events
 */
class SecurityAuditLogger {
public:
    enum class EventType {
        LOGIN_SUCCESS,
        LOGIN_FAILURE,
        LOGOUT,
        PERMISSION_DENIED,
        PRIVILEGE_ESCALATION,
        CONFIGURATION_CHANGE,
        USER_CREATED,
        USER_DELETED,
        ROLE_ASSIGNED,
        ROLE_REMOVED,
        MFA_ENABLED,
        MFA_DISABLED,
        TOKEN_ISSUED,
        TOKEN_REVOKED,
        SUSPICIOUS_ACTIVITY
    };
    
    struct AuditEvent {
        std::string event_id;
        EventType event_type;
        std::string user_id;
        std::string source_ip;
        std::string user_agent;
        std::string resource;
        std::string action;
        std::string result;
        std::string details;
        std::chrono::system_clock::time_point timestamp;
    };
    
private:
    std::string log_file_;
    std::vector<AuditEvent> event_buffer_;
    std::mutex log_mutex_;
    
public:
    SecurityAuditLogger(const std::string& log_file = "security_audit.log");
    
    void LogEvent(EventType type, const std::string& user_id, const std::string& source_ip,
                 const std::string& resource, const std::string& action, 
                 const std::string& result, const std::string& details = "");
    
    void LogLoginAttempt(const std::string& username, const std::string& source_ip, bool success);
    void LogPermissionDenied(const std::string& user_id, const std::string& resource, 
                           const std::string& permission);
    void LogConfigurationChange(const std::string& user_id, const std::string& setting,
                              const std::string& old_value, const std::string& new_value);
    
    std::vector<AuditEvent> GetEvents(const std::chrono::system_clock::time_point& start_time,
                                     const std::chrono::system_clock::time_point& end_time);
    std::vector<AuditEvent> GetUserEvents(const std::string& user_id);
    
    void GenerateSecurityReport(const std::string& output_file);
    
private:
    void WriteEventToLog(const AuditEvent& event);
    std::string EventTypeToString(EventType type);
    std::string GenerateEventId();
};

/**
 * Enterprise authentication manager
 */
class EnterpriseAuthManager {
private:
    std::vector<std::unique_ptr<AuthenticationProvider>> auth_providers_;
    std::unique_ptr<MFAProvider> mfa_provider_;
    std::unique_ptr<RBACManager> rbac_manager_;
    std::unique_ptr<SecurityAuditLogger> audit_logger_;
    
    std::unordered_map<std::string, AuthToken> active_tokens_;
    std::mutex tokens_mutex_;
    
    std::string config_file_;
    bool mfa_required_;
    int token_lifetime_minutes_;
    
public:
    EnterpriseAuthManager(const std::string& config_file = "auth_config.json");
    ~EnterpriseAuthManager();
    
    // Initialization
    bool Initialize();
    bool LoadConfiguration();
    bool SaveConfiguration();
    
    // Authentication
    AuthToken Authenticate(const std::string& username, const std::string& password,
                          const std::string& mfa_code = "", const std::string& source_ip = "");
    bool ValidateToken(const std::string& token_value);
    bool RevokeToken(const std::string& token_value);
    void RevokeAllUserTokens(const std::string& user_id);
    
    // Authorization
    bool HasPermission(const std::string& token_value, Permission permission);
    bool HasPermission(const std::string& token_value, const std::string& resource, 
                      const std::string& action);
    
    // User management
    UserIdentity GetUserIdentity(const std::string& token_value);
    bool UpdateUserProfile(const std::string& token_value, const UserIdentity& profile);
    
    // Provider management
    bool AddAuthProvider(std::unique_ptr<AuthenticationProvider> provider);
    bool RemoveAuthProvider(AuthProvider provider_type);
    std::vector<AuthProvider> GetAvailableProviders();
    
    // MFA management
    bool EnableMFA(const std::string& user_id, MFAProvider::MFAType type);
    bool DisableMFA(const std::string& user_id, MFAProvider::MFAType type);
    bool IsMFARequired(const std::string& user_id);
    
    // Security monitoring
    void EnableSecurityMonitoring();
    void DisableSecurityMonitoring();
    std::vector<SecurityAuditLogger::AuditEvent> GetSecurityEvents(
        const std::chrono::system_clock::time_point& start_time,
        const std::chrono::system_clock::time_point& end_time);
    
private:
    AuthToken GenerateToken(const UserIdentity& user, const std::string& source_ip);
    bool IsTokenExpired(const AuthToken& token);
    void CleanupExpiredTokens();
    std::string GenerateTokenValue();
    
    AuthenticationProvider* FindProvider(AuthProvider provider_type);
    void LogSecurityEvent(SecurityAuditLogger::EventType type, const std::string& user_id,
                         const std::string& source_ip, const std::string& details);
};

// Global enterprise authentication manager
extern std::unique_ptr<EnterpriseAuthManager> enterprise_auth;
