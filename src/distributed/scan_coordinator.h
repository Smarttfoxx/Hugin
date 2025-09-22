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
#include <condition_variable>
#include <queue>
#include <atomic>
#include <chrono>
#include <future>
#include "../utilities/output_formats.h"

/**
 * Distributed scanning architecture for large-scale network discovery
 */

enum class NodeRole {
    COORDINATOR,    // Central coordination and result aggregation
    SCANNER,        // Distributed scanning node
    HYBRID         // Can act as both coordinator and scanner
};

enum class ScanTaskStatus {
    PENDING,
    ASSIGNED,
    IN_PROGRESS,
    COMPLETED,
    FAILED,
    TIMEOUT
};

/**
 * Represents a scanning task that can be distributed to nodes
 */
struct ScanTask {
    std::string task_id;
    std::string target_ip;
    std::vector<int> ports;
    std::string protocol;
    bool service_detection;
    bool os_detection;
    int timeout_seconds;
    ScanTaskStatus status;
    std::string assigned_node;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point assigned_at;
    std::chrono::system_clock::time_point completed_at;
    ScanResult result;
    std::string error_message;
};

/**
 * Information about a scanning node in the distributed system
 */
struct ScanNode {
    std::string node_id;
    std::string hostname;
    std::string ip_address;
    int port;
    NodeRole role;
    bool active;
    int max_concurrent_tasks;
    int current_tasks;
    std::chrono::system_clock::time_point last_heartbeat;
    std::unordered_map<std::string, std::string> capabilities;
    std::vector<std::string> assigned_tasks;
};

/**
 * Network communication protocol for distributed scanning
 */
class DistributedProtocol {
public:
    enum class MessageType {
        HEARTBEAT,
        TASK_ASSIGNMENT,
        TASK_RESULT,
        TASK_STATUS_UPDATE,
        NODE_REGISTRATION,
        NODE_DEREGISTRATION,
        SCAN_REQUEST,
        SCAN_RESPONSE,
        ERROR_REPORT
    };
    
    struct Message {
        MessageType type;
        std::string sender_id;
        std::string recipient_id;
        std::string payload;
        std::chrono::system_clock::time_point timestamp;
        std::string message_id;
    };
    
    static std::string SerializeMessage(const Message& message);
    static Message DeserializeMessage(const std::string& data);
    static std::string SerializeScanTask(const ScanTask& task);
    static ScanTask DeserializeScanTask(const std::string& data);
    static std::string SerializeScanResult(const ScanResult& result);
    static ScanResult DeserializeScanResult(const std::string& data);
};

/**
 * Central coordinator for distributed scanning operations
 */
class ScanCoordinator {
private:
    std::string coordinator_id_;
    std::vector<ScanNode> registered_nodes_;
    std::queue<ScanTask> pending_tasks_;
    std::unordered_map<std::string, ScanTask> active_tasks_;
    std::unordered_map<std::string, ScanTask> completed_tasks_;
    
    std::mutex nodes_mutex_;
    std::mutex tasks_mutex_;
    std::condition_variable task_available_;
    
    std::atomic<bool> running_;
    std::thread coordinator_thread_;
    std::thread heartbeat_thread_;
    
    int listen_port_;
    int max_task_timeout_;
    int heartbeat_interval_;
    
public:
    ScanCoordinator(const std::string& coordinator_id, int listen_port = 8080);
    ~ScanCoordinator();
    
    // Coordinator lifecycle
    bool Start();
    void Stop();
    bool IsRunning() const;
    
    // Node management
    bool RegisterNode(const ScanNode& node);
    bool DeregisterNode(const std::string& node_id);
    std::vector<ScanNode> GetActiveNodes() const;
    ScanNode* FindNode(const std::string& node_id);
    
    // Task management
    std::string SubmitScanJob(const std::vector<std::string>& targets, 
                             const std::vector<int>& ports,
                             bool service_detection = true,
                             bool os_detection = false);
    
    bool SubmitScanTask(const ScanTask& task);
    ScanTask* GetTask(const std::string& task_id);
    std::vector<ScanTask> GetTasksByStatus(ScanTaskStatus status);
    
    // Result aggregation
    bool SubmitTaskResult(const std::string& task_id, const ScanResult& result);
    bool SubmitTaskError(const std::string& task_id, const std::string& error);
    ScanResult GetAggregatedResults(const std::string& job_id);
    
    // Load balancing
    ScanNode* SelectOptimalNode(const ScanTask& task);
    void RebalanceTasks();
    
    // Monitoring and statistics
    struct CoordinatorStats {
        int total_nodes;
        int active_nodes;
        int pending_tasks;
        int active_tasks;
        int completed_tasks;
        int failed_tasks;
        double average_task_time;
        double throughput_tasks_per_second;
    };
    
    CoordinatorStats GetStatistics() const;
    void GenerateStatusReport(std::ostream& output);
    
private:
    void CoordinatorLoop();
    void HeartbeatLoop();
    void AssignTasks();
    void CheckTaskTimeouts();
    void HandleNodeTimeout(const std::string& node_id);
    std::string GenerateTaskId();
    std::string GenerateJobId();
};

/**
 * Distributed scanning node that executes tasks
 */
class ScanNode {
private:
    std::string node_id_;
    std::string coordinator_host_;
    int coordinator_port_;
    NodeRole role_;
    
    std::atomic<bool> running_;
    std::thread worker_thread_;
    std::thread heartbeat_thread_;
    
    std::queue<ScanTask> task_queue_;
    std::unordered_map<std::string, std::future<ScanResult>> active_scans_;
    std::mutex queue_mutex_;
    std::condition_variable task_available_;
    
    int max_concurrent_tasks_;
    int heartbeat_interval_;
    
public:
    ScanNode(const std::string& node_id, 
             const std::string& coordinator_host,
             int coordinator_port,
             NodeRole role = NodeRole::SCANNER);
    ~ScanNode();
    
    // Node lifecycle
    bool Start();
    void Stop();
    bool IsRunning() const;
    
    // Task execution
    bool AcceptTask(const ScanTask& task);
    ScanResult ExecuteTask(const ScanTask& task);
    void ProcessTaskQueue();
    
    // Communication with coordinator
    bool RegisterWithCoordinator();
    bool SendHeartbeat();
    bool SendTaskResult(const std::string& task_id, const ScanResult& result);
    bool SendTaskError(const std::string& task_id, const std::string& error);
    
    // Configuration
    void SetMaxConcurrentTasks(int max_tasks);
    void SetHeartbeatInterval(int interval_seconds);
    
    // Monitoring
    struct NodeStats {
        int tasks_completed;
        int tasks_failed;
        int current_load;
        double average_task_time;
        std::chrono::system_clock::time_point last_task_completion;
    };
    
    NodeStats GetStatistics() const;
    
private:
    void WorkerLoop();
    void HeartbeatLoop();
    std::string GenerateNodeId();
};

/**
 * High-level distributed scanning manager
 */
class DistributedScanManager {
private:
    std::unique_ptr<ScanCoordinator> coordinator_;
    std::vector<std::unique_ptr<ScanNode>> local_nodes_;
    
    std::string config_file_;
    bool auto_scale_;
    int min_nodes_;
    int max_nodes_;
    
public:
    DistributedScanManager(const std::string& config_file = "");
    ~DistributedScanManager();
    
    // System management
    bool Initialize();
    bool StartCoordinator(int port = 8080);
    bool StartLocalNodes(int count = 1);
    void Shutdown();
    
    // Scanning operations
    std::string ScanNetwork(const std::string& network_cidr,
                           const std::vector<int>& ports,
                           bool service_detection = true,
                           bool os_detection = false);
    
    std::string ScanTargets(const std::vector<std::string>& targets,
                           const std::vector<int>& ports,
                           bool service_detection = true,
                           bool os_detection = false);
    
    // Result management
    ScanResult GetResults(const std::string& job_id);
    bool ExportResults(const std::string& job_id, 
                      const std::string& format,
                      const std::string& filename);
    
    // Monitoring and control
    void MonitorProgress(const std::string& job_id);
    bool CancelJob(const std::string& job_id);
    void GenerateSystemReport();
    
    // Auto-scaling
    void EnableAutoScaling(int min_nodes, int max_nodes);
    void DisableAutoScaling();
    void ScaleUp(int additional_nodes);
    void ScaleDown(int nodes_to_remove);
    
private:
    bool LoadConfiguration();
    void SaveConfiguration();
    std::vector<std::string> ExpandCIDR(const std::string& cidr);
    void OptimizeTaskDistribution();
};

/**
 * Cloud integration for elastic scaling
 */
class CloudScalingManager {
public:
    enum class CloudProvider {
        AWS,
        AZURE,
        GCP,
        DOCKER,
        KUBERNETES
    };
    
private:
    CloudProvider provider_;
    std::string credentials_file_;
    std::string instance_template_;
    std::vector<std::string> active_instances_;
    
public:
    CloudScalingManager(CloudProvider provider, const std::string& credentials_file);
    
    // Instance management
    bool LaunchScanNodes(int count, const std::string& coordinator_endpoint);
    bool TerminateNodes(const std::vector<std::string>& instance_ids);
    std::vector<std::string> GetActiveInstances();
    
    // Auto-scaling policies
    void SetScalingPolicy(int min_instances, int max_instances, 
                         double cpu_threshold, double memory_threshold);
    void EnableAutoScaling();
    void DisableAutoScaling();
    
    // Cost optimization
    double EstimateCost(int instances, int hours);
    void OptimizeInstanceTypes();
    
private:
    bool LaunchAWSInstance(const std::string& coordinator_endpoint);
    bool LaunchDockerContainer(const std::string& coordinator_endpoint);
    bool LaunchKubernetesJob(const std::string& coordinator_endpoint);
};

/**
 * Security and authentication for distributed scanning
 */
class DistributedSecurity {
private:
    std::string ca_cert_path_;
    std::string node_cert_path_;
    std::string node_key_path_;
    std::unordered_map<std::string, std::string> api_keys_;
    
public:
    DistributedSecurity(const std::string& ca_cert, 
                       const std::string& node_cert,
                       const std::string& node_key);
    
    // Authentication
    bool AuthenticateNode(const std::string& node_id, const std::string& credentials);
    std::string GenerateAPIKey(const std::string& node_id);
    bool ValidateAPIKey(const std::string& node_id, const std::string& api_key);
    
    // Encryption
    std::string EncryptMessage(const std::string& message, const std::string& recipient_key);
    std::string DecryptMessage(const std::string& encrypted_message, const std::string& private_key);
    
    // Certificate management
    bool ValidateCertificate(const std::string& cert_data);
    bool IsNodeAuthorized(const std::string& node_id);
    void RevokeNodeAccess(const std::string& node_id);
    
    // Audit logging
    void LogSecurityEvent(const std::string& event_type, 
                         const std::string& node_id,
                         const std::string& details);
};

// Global distributed scanning manager
extern std::unique_ptr<DistributedScanManager> distributed_manager;
