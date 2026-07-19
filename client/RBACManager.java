```java
package client;

import java.io.*;
import java.util.*;

public class RBACManager {
    private static final String ROLES_FILE = "roles.dat";
    private Map<String, Role> userRoles = new HashMap<>();
    private List<LogEntry> auditLog = new ArrayList<>();

    public enum Role {
        ADMIN, USER, GUEST
    }

    public enum Permission {
        ENCRYPT_FILE, DECRYPT_FILE, DELETE_KEYS, VIEW_LOGS, DELETE_LOGS
    }

    public static class LogEntry implements Serializable { // Make LogEntry Serializable
        private String username;
        private String action;
        private long timestamp;

        public LogEntry(String username, String action) {
            this.username = username;
            this.action = action;
            this.timestamp = System.currentTimeMillis();
        }

        @Override
        public String toString() {
            return String.format("[%s] %s: %s", new java.util.Date(timestamp), username, action);
        }
    }

    public RBACManager() {
        loadRoles();
        loadAuditLog();
    }

    public void assignRole(String username, Role role) {
        userRoles.put(username, role);
        saveRoles();
        logAction(username, "Assigned role: " + role);
    }

    public boolean hasPermission(String username, Permission permission) {
        Role role = userRoles.getOrDefault(username, Role.GUEST);
        switch (role) {
            case ADMIN:
                return true;
            case USER:
                return permission == Permission.ENCRYPT_FILE || permission == Permission.DECRYPT_FILE;
            case GUEST:
                return permission == Permission.ENCRYPT_FILE;
            default:
                return false;
        }
    }

    public void logAction(String username, String action) {
        auditLog.add(new LogEntry(username, action));
        saveAuditLog();
    }

    public List<LogEntry> getAuditLog(String username) {
        if (hasPermission(username, Permission.VIEW_LOGS)) {
            return new ArrayList<>(auditLog);
        }
        return Collections.emptyList();
    }

    public void deleteLogs(String username) {
        if (hasPermission(username, Permission.DELETE_LOGS)) {
            auditLog.clear();
            saveAuditLog();
            logAction(username, "Deleted audit logs");
        }
    }

    @SuppressWarnings("unchecked")
    private void loadRoles() {
        File rolesFile = new File(ROLES_FILE);
        try {
            if (rolesFile.exists()) {
                try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(rolesFile))) {
                    userRoles = (Map<String, Role>) in.readObject();
                }
            } else {
                userRoles.put("admin", Role.ADMIN);
                saveRoles();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void saveRoles() {
        try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(ROLES_FILE))) {
            out.writeObject(userRoles);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void saveAuditLog() {
        try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("audit_log.dat"))) {
            out.writeObject(auditLog);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @SuppressWarnings("unchecked")
    public void loadAuditLog() {
        File logFile = new File("audit_log.dat");
        if (logFile.exists()) {
            try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(logFile))) {
                auditLog = (List<LogEntry>) in.readObject();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
```