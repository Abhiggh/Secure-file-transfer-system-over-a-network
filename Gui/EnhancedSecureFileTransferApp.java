package Gui;

import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import client.ClientNetworkUtil;
import java.awt.image.BufferedImage;
import javax.imageio.ImageIO;
import java.net.ConnectException;
import java.util.Date;
import java.util.Arrays;
import java.math.BigInteger;

public class EnhancedSecureFileTransferApp extends JFrame {
    private static final String LOGIN_PANEL = "Login Panel";
    private static final String TRANSFER_PANEL = "Transfer Panel";
    private static final String CHAT_PANEL = "Chat Panel";
    
    private static final String AES_ALGO = "AES";
    private static final String BLOWFISH_ALGO = "Blowfish";
    
    private static final String USER_DATABASE_FILE = "users.dat";
    private static final String PRIVATE_KEY_FILE = "private.key";
    private static final String PUBLIC_KEY_FILE = "public.key";
    private Map<String, User> userDatabase = new HashMap<>();

    private static final String LOG_FILE_PATH = "received_files/audit.log";

    private JPanel mainPanel;
    private CardLayout cardLayout;
    
    private JTextField usernameField;
    private JPasswordField passwordField;
    private JButton loginButton;
    private JButton registerButton;
    
    private JTextField filePathField;
    private JTextField coverImagePathField;
    private JButton browseButton;
    private JButton browseCoverImageButton;
    private JTextArea statusArea;
    private JProgressBar progressBar;
    private JButton encryptSendButton;
    private JButton decryptReceiveButton;
    private JButton logoutButton;
    private JButton viewLogsButton;
    private JButton deleteKeysLogsButton;
    private JComboBox<String> algorithmCombo;
    private JComboBox<String> keyHandlingCombo;
    private File selectedFile;
    private File selectedCoverImage;
    
    private JTextArea chatArea;
    private JTextField messageField;
    private JButton sendMessageButton;
    private JButton backToTransferButton;
    private JLabel chatbotAvatar;
    private List<String> chatHistory = new ArrayList<>();
    private String username = "";
    private KeyPair rsaKeyPair;
    private List<String> pendingStatusMessages = new ArrayList<>();

    public EnhancedSecureFileTransferApp() {
        setTitle("Secure File Transfer");
        setSize(800, 600);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        
        cardLayout = new CardLayout();
        mainPanel = new JPanel(cardLayout);

        createLoginPanel();
        createTransferPanel();
        createChatPanel();
        
        add(mainPanel);

        loadUserDatabase();
        loadOrGenerateRSAKeys();

        if (statusArea != null) {
            for (String message : pendingStatusMessages) {
                statusArea.append(message + "\n");
            }
            pendingStatusMessages.clear();
        }
    }
    private void loadOrGenerateRSAKeys() {
        try {
            File privateKeyFile = new File(PRIVATE_KEY_FILE);
            File publicKeyFile = new File(PUBLIC_KEY_FILE);
            
            if (privateKeyFile.exists() && publicKeyFile.exists()) {
                byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
                byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
                
                PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateKeyBytes);
                X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKeyBytes);
                
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PrivateKey privateKey = keyFactory.generatePrivate(privateSpec);
                PublicKey publicKey = keyFactory.generatePublic(publicSpec);
                
                if (!(publicKey instanceof RSAPublicKey) || !(privateKey instanceof RSAPrivateKey)) {
                    throw new IllegalStateException("Loaded keys are not RSA keys: public=" + publicKey.getClass().getName() + ", private=" + privateKey.getClass().getName());
                }
                rsaKeyPair = new KeyPair(publicKey, privateKey);
                appendStatus("Loaded existing RSA key pair.");
                RSAPublicKey rsaPub = (RSAPublicKey) publicKey;
                RSAPrivateKey rsaPriv = (RSAPrivateKey) privateKey;
                appendStatus("Public key modulus: " + rsaPub.getModulus().toString(16));
                appendStatus("Private key modulus: " + rsaPriv.getModulus().toString(16));
            } else {
                KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
                keyPairGen.initialize(2048);
                rsaKeyPair = keyPairGen.generateKeyPair();
                
                Files.write(privateKeyFile.toPath(), rsaKeyPair.getPrivate().getEncoded());
                Files.write(publicKeyFile.toPath(), rsaKeyPair.getPublic().getEncoded());
                appendStatus("Generated and saved new RSA key pair.");
                
                if (!(rsaKeyPair.getPublic() instanceof RSAPublicKey) || !(rsaKeyPair.getPrivate() instanceof RSAPrivateKey)) {
                    throw new IllegalStateException("Generated keys are not RSA keys: public=" + rsaKeyPair.getPublic().getClass().getName() + ", private=" + rsaKeyPair.getPrivate().getClass().getName());
                }
                RSAPublicKey rsaPub = (RSAPublicKey) rsaKeyPair.getPublic();
                RSAPrivateKey rsaPriv = (RSAPrivateKey) rsaKeyPair.getPrivate();
                appendStatus("Public key modulus: " + rsaPub.getModulus().toString(16));
                appendStatus("Private key modulus: " + rsaPriv.getModulus().toString(16));
            }
        } catch (Exception e) {
            e.printStackTrace();
            appendStatus("Error loading/generating RSA keys: " + e.getMessage());
        }
    }
    private void appendStatus(String message) {
        if (statusArea != null) {
            statusArea.append(message + "\n");
        } else {
            pendingStatusMessages.add(message);
        }
    }
    private void createLoginPanel() {
        JPanel loginPanel = new JPanel(new BorderLayout());
        loginPanel.setBackground(new Color(240, 248, 255)); 

        JPanel titlePanel = new JPanel();
        titlePanel.setBackground(new Color(240, 248, 255));
        JLabel titleLabel = new JLabel("Secure File Transfer");
        titleLabel.setFont(new Font("Arial", Font.BOLD, 24));
        titleLabel.setForeground(new Color(70, 130, 180)); 
        titlePanel.add(titleLabel);
        
        JLabel subtitleLabel = new JLabel("Login to access secure file transfer");
        subtitleLabel.setFont(new Font("Arial", Font.ITALIC, 14));
        JPanel subtitlePanel = new JPanel();
        subtitlePanel.setBackground(new Color(240, 248, 255));
        subtitlePanel.add(subtitleLabel);
        
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBackground(new Color(240, 248, 255));
        headerPanel.add(titlePanel, BorderLayout.NORTH);
        headerPanel.add(subtitlePanel, BorderLayout.CENTER);
        headerPanel.setBorder(new EmptyBorder(30, 0, 20, 0));
        
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBackground(new Color(240, 248, 255));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        
        JLabel usernameLabel = new JLabel("Username:");
        usernameField = new JTextField(20);
        
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.EAST;
        formPanel.add(usernameLabel, gbc);
        
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        formPanel.add(usernameField, gbc);
        
        JLabel passwordLabel = new JLabel("Password:");
        passwordField = new JPasswordField(20);
        
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.anchor = GridBagConstraints.EAST;
        formPanel.add(passwordLabel, gbc);
        
        gbc.gridx = 1;
        gbc.gridy = 1;
        gbc.anchor = GridBagConstraints.WEST;
        formPanel.add(passwordField, gbc);
        
        JPanel buttonPanel = new JPanel();
        buttonPanel.setBackground(new Color(240, 248, 255));
        
        loginButton = new JButton("Login");
        loginButton.setBackground(new Color(70, 130, 180));
        loginButton.setForeground(Color.WHITE);
        loginButton.setPreferredSize(new Dimension(150, 40));
        loginButton.setFocusPainted(false);
        loginButton.setBorderPainted(false);
        loginButton.setOpaque(true);
        
        registerButton = new JButton("Register");
        registerButton.setBackground(new Color(70, 130, 180));
        registerButton.setForeground(Color.WHITE);
        registerButton.setPreferredSize(new Dimension(150, 40));
        registerButton.setFocusPainted(false);
        registerButton.setBorderPainted(false);
        registerButton.setOpaque(true);
        
        buttonPanel.add(loginButton);
        buttonPanel.add(Box.createRigidArea(new Dimension(20, 0)));
        buttonPanel.add(registerButton);
        
        loginButton.addActionListener(e -> handleLogin());
        registerButton.addActionListener(e -> handleRegister());
        
        JPanel centerPanel = new JPanel(new BorderLayout());
        centerPanel.setBackground(new Color(240, 248, 255));
        centerPanel.add(formPanel, BorderLayout.CENTER);
        centerPanel.add(buttonPanel, BorderLayout.SOUTH);
        centerPanel.setBorder(new EmptyBorder(0, 50, 30, 50));
        
        loginPanel.add(headerPanel, BorderLayout.NORTH);
        loginPanel.add(centerPanel, BorderLayout.CENTER);
        mainPanel.add(loginPanel, LOGIN_PANEL);
    }
    private void deleteKeysAndLogs() {
        appendStatus("\nDeleting keys and logs...\n");

        File directory = new File(".");
        File[] keyFiles = directory.listFiles((dir, name) -> name.toLowerCase().endsWith(".key") || name.toLowerCase().endsWith(".sig"));
        if (keyFiles != null && keyFiles.length > 0) {
            for (File keyFile : keyFiles) {
                if (keyFile.delete()) {
                    appendStatus("Deleted: " + keyFile.getAbsolutePath());
                } else {
                    appendStatus("Failed to delete: " + keyFile.getAbsolutePath());
                }
            }
        }
        File keyDir = new File("received_files");
        if (keyDir.exists() && keyDir.isDirectory()) {
            deleteKeysRecursively(keyDir);
        }
        File auditLog = new File("received_files/audit.log");
        
        if (auditLog.exists()) {
            if (auditLog.delete()) {
                appendStatus("Deleted: " + auditLog.getAbsolutePath());
            } else {
                appendStatus("Failed to delete: " + auditLog.getAbsolutePath());
            }
        } else {
            appendStatus("No audit log found.");
        }

        appendStatus("Delete process completed.");
    }
    private void deleteKeysRecursively(File dir) {
        File[] files = dir.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    deleteKeysRecursively(file);
                } else if (file.getName().toLowerCase().endsWith(".key") || file.getName().toLowerCase().endsWith(".stego.png") || file.getName().toLowerCase().endsWith(".sig")) {
                    if (file.delete()) {
                        appendStatus("Deleted: " + file.getAbsolutePath());
                    } else {
                        appendStatus("Failed to delete: " + file.getAbsolutePath());
                    }
                }
            }
        }
    }
    class User implements Serializable {
        private static final long serialVersionUID = -5639772853664617958L;
        String username;
        String password;
        String role;
        public User(String username, String password, String role) {
            this.username = username;
            this.password = password;
            this.role = role;
        }
    }
    private void createTransferPanel() {
        JPanel transferPanel = new JPanel(new BorderLayout(10, 10));
        transferPanel.setBackground(new Color(240, 248, 255));
        transferPanel.setBorder(new EmptyBorder(20, 20, 20, 20));
        
        JLabel titleLabel = new JLabel("Secure File Transfer");
        titleLabel.setFont(new Font("Arial", Font.BOLD, 24));
        titleLabel.setForeground(new Color(70, 130, 180));
        titleLabel.setHorizontalAlignment(SwingConstants.CENTER);
        transferPanel.add(titleLabel, BorderLayout.NORTH);
        
        JPanel filePanel = new JPanel(new BorderLayout(5, 5));
        filePanel.setBackground(new Color(240, 248, 255));
        JLabel fileLabel = new JLabel("File:");
        filePathField = new JTextField();
        filePathField.setEditable(false);
        browseButton = new JButton("Browse");
        browseButton.setBackground(new Color(70, 130, 180));
        browseButton.setForeground(Color.WHITE);
        browseButton.setFocusPainted(false);
        browseButton.setBorderPainted(false);
        browseButton.setOpaque(true);
        
        filePanel.add(fileLabel, BorderLayout.WEST);
        filePanel.add(filePathField, BorderLayout.CENTER);
        filePanel.add(browseButton, BorderLayout.EAST);
        
        JPanel coverImagePanel = new JPanel(new BorderLayout(5, 5));
        coverImagePanel.setBackground(new Color(240, 248, 255));
        JLabel coverImageLabel = new JLabel("Cover Image:");
        coverImagePathField = new JTextField();
        coverImagePathField.setEditable(false);
        browseCoverImageButton = new JButton("Browse Image");
        browseCoverImageButton.setBackground(new Color(70, 130, 180));
        browseCoverImageButton.setForeground(Color.WHITE);
        browseCoverImageButton.setFocusPainted(false);
        browseCoverImageButton.setBorderPainted(false);
        browseCoverImageButton.setOpaque(true);
        
        coverImagePanel.add(coverImageLabel, BorderLayout.WEST);
        coverImagePanel.add(coverImagePathField, BorderLayout.CENTER);
        coverImagePanel.add(browseCoverImageButton, BorderLayout.EAST);
        
        JPanel inputPanel = new JPanel(new GridLayout(2, 1, 5, 5));
        inputPanel.setBackground(new Color(240, 248, 255));
        inputPanel.add(filePanel);
        inputPanel.add(coverImagePanel);
        
        JPanel statusPanel = new JPanel(new BorderLayout(5, 5));
        statusPanel.setBackground(new Color(240, 248, 255));
        JLabel statusLabel = new JLabel("Status:");
        statusArea = new JTextArea();
        statusArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(statusArea);
        scrollPane.setPreferredSize(new Dimension(400, 200));
        
        statusPanel.add(statusLabel, BorderLayout.NORTH);
        statusPanel.add(scrollPane, BorderLayout.CENTER);
        
        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setString("0%");
        statusPanel.add(progressBar, BorderLayout.SOUTH);
        
        JPanel optionsPanel = new JPanel(new GridLayout(1, 2, 10, 0));
        optionsPanel.setBackground(new Color(240, 248, 255));

        JPanel algoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        algoPanel.setBackground(new Color(240, 248, 255));
        JLabel algoLabel = new JLabel("Encryption:");
        algorithmCombo = new JComboBox<>(new String[]{"AES", "Blowfish", "Double Encryption (AES + Blowfish + Wavelet)"});
        algoPanel.add(algoLabel);
        algoPanel.add(algorithmCombo);

        JPanel keyHandlingPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        keyHandlingPanel.setBackground(new Color(240, 248, 255));
        JLabel keyHandlingLabel = new JLabel("Key Handling:");
        keyHandlingCombo = new JComboBox<>(new String[]{"Normal Encryption (Key File)", "Steganography (Key in Image)"});
        keyHandlingPanel.add(keyHandlingLabel);
        keyHandlingPanel.add(keyHandlingCombo);

        optionsPanel.add(algoPanel);
        optionsPanel.add(keyHandlingPanel);
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        buttonPanel.setBackground(new Color(240, 248, 255));
        
        encryptSendButton = new JButton("Encrypt & Send");
        encryptSendButton.setBackground(new Color(70, 130, 180));
        encryptSendButton.setForeground(Color.WHITE);
        encryptSendButton.setFocusPainted(false);
        encryptSendButton.setBorderPainted(false);
        encryptSendButton.setOpaque(true);
        
        decryptReceiveButton = new JButton("Decrypt & Receive");
        decryptReceiveButton.setBackground(new Color(70, 130, 180));
        decryptReceiveButton.setForeground(Color.WHITE);
        decryptReceiveButton.setFocusPainted(false);
        decryptReceiveButton.setBorderPainted(false);
        decryptReceiveButton.setOpaque(true);
        
        logoutButton = new JButton("Logout");
        logoutButton.setBackground(new Color(178, 34, 34));  
        logoutButton.setForeground(Color.WHITE);
        logoutButton.setFocusPainted(false);
        logoutButton.setBorderPainted(false);
        logoutButton.setOpaque(true);

        viewLogsButton = new JButton("View Logs");
        viewLogsButton.setBackground(new Color(70, 130, 180));
        viewLogsButton.setForeground(Color.WHITE);
        viewLogsButton.setFocusPainted(false);
        viewLogsButton.setBorderPainted(false);
        viewLogsButton.setOpaque(true);

        deleteKeysLogsButton = new JButton("Delete Keys & Logs");
        deleteKeysLogsButton.setBackground(new Color(178, 34, 34));
        deleteKeysLogsButton.setForeground(Color.WHITE);
        deleteKeysLogsButton.setFocusPainted(false);
        deleteKeysLogsButton.setBorderPainted(false);
        deleteKeysLogsButton.setOpaque(true);

        JButton chatButton = new JButton("Open Chat");
        chatButton.setBackground(new Color(60, 179, 113)); 
        chatButton.setForeground(Color.WHITE);
        chatButton.setFocusPainted(false);
        chatButton.setBorderPainted(false);
        chatButton.setOpaque(true);
        
        buttonPanel.add(viewLogsButton);
        buttonPanel.add(deleteKeysLogsButton);
        buttonPanel.add(encryptSendButton);
        buttonPanel.add(decryptReceiveButton);
        buttonPanel.add(chatButton);
        buttonPanel.add(logoutButton);
        
        deleteKeysLogsButton.addActionListener(e -> deleteKeysAndLogs());
        viewLogsButton.addActionListener(e -> viewLogs());

        JPanel centerPanel = new JPanel(new BorderLayout(5, 10));
        centerPanel.setBackground(new Color(240, 248, 255));
        centerPanel.add(inputPanel, BorderLayout.NORTH);
        centerPanel.add(statusPanel, BorderLayout.CENTER);
        centerPanel.add(optionsPanel, BorderLayout.SOUTH);
        
        transferPanel.add(centerPanel, BorderLayout.CENTER);
        transferPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        browseButton.addActionListener(e -> chooseFile());
        browseCoverImageButton.addActionListener(e -> chooseCoverImage());
        encryptSendButton.addActionListener(e -> sendFileToServer());
        decryptReceiveButton.addActionListener(e -> receiveFile());
        logoutButton.addActionListener(e -> logout());
        chatButton.addActionListener(e -> showChatPanel());

        mainPanel.add(transferPanel, TRANSFER_PANEL);
    }
    private void logAccess(String user, String action) {
        try {
            File logFile = new File(LOG_FILE_PATH);
            File parentDir = logFile.getParentFile();
            if (!parentDir.exists()) {
                parentDir.mkdirs();
            }
            try (PrintWriter out = new PrintWriter(new FileWriter(logFile, true))) {
                out.println(new Date() + " - " + user + " - " + action);
            }
        } catch (Exception e) {
            System.err.println("Error writing to audit.log: " + e.getMessage());
            e.printStackTrace();
        }
    }
    private void viewLogs() {
        try {
            File logFile = new File(LOG_FILE_PATH);
            if (!logFile.exists()) {
                JOptionPane.showMessageDialog(this, "No logs found.", "Logs", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            String logs = new String(Files.readAllBytes(logFile.toPath()));
            JTextArea logArea = new JTextArea(logs);
            logArea.setEditable(false);
            JScrollPane scrollPane = new JScrollPane(logArea);
            scrollPane.setPreferredSize(new Dimension(500, 300));
            JOptionPane.showMessageDialog(this, scrollPane, "Audit Logs", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(this, "Error reading logs: " + e.getMessage(), "Logs Error", JOptionPane.ERROR_MESSAGE);
        }
    }
    private void createChatPanel() {
        JPanel chatPanel = new JPanel(new BorderLayout(10, 10));
        chatPanel.setBackground(new Color(240, 248, 255));
        chatPanel.setBorder(new EmptyBorder(20, 20, 20, 20));
        
        JLabel titleLabel = new JLabel("Secure Chat");
        titleLabel.setFont(new Font("Arial", Font.BOLD, 24));
        titleLabel.setForeground(new Color(70, 130, 180));
        titleLabel.setHorizontalAlignment(SwingConstants.CENTER);
        chatPanel.add(titleLabel, BorderLayout.NORTH);
        
        JPanel chatAreaPanel = new JPanel(new BorderLayout(10, 0));
        chatAreaPanel.setBackground(new Color(240, 248, 255));
        
        JPanel avatarPanel = new JPanel(new BorderLayout());
        avatarPanel.setBackground(new Color(240, 248, 255));
        avatarPanel.setPreferredSize(new Dimension(120, 120));
        
        chatbotAvatar = new JLabel();
        chatbotAvatar.setHorizontalAlignment(SwingConstants.CENTER);
        chatbotAvatar.setPreferredSize(new Dimension(100, 100));
        try {
        chatbotAvatar.setIcon(new ImageIcon("chatbot.png"));
        } catch (Exception e) {
        System.err.println("Failed to load chatbot image: " + e.getMessage());
        chatbotAvatar.setText("Bot");
    }
        
        avatarPanel.setPreferredSize(new Dimension(120, 120));
        avatarPanel.setBackground(new Color(245, 250, 255));
        avatarPanel.setBorder(BorderFactory.createLineBorder(new Color(180, 220, 180), 2));
        avatarPanel.add(chatbotAvatar, BorderLayout.CENTER);

        avatarPanel.setBorder(new EmptyBorder(0, 0, 0, 10));
        chatArea = new JTextArea();
        chatArea.setEditable(false);
        chatArea.setLineWrap(true);
        chatArea.setWrapStyleWord(true);
        chatArea.setFont(new Font("Arial", Font.PLAIN, 14));
        chatArea.setBackground(new Color(250, 250, 255));
        chatArea.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        JScrollPane chatScrollPane = new JScrollPane(chatArea);
        chatScrollPane.setPreferredSize(new Dimension(400, 300));
        chatScrollPane.setBorder(BorderFactory.createLineBorder(new Color(70, 130, 180), 1));
        
        chatAreaPanel.add(avatarPanel, BorderLayout.WEST);
        chatAreaPanel.add(chatScrollPane, BorderLayout.CENTER);
        chatPanel.add(chatAreaPanel, BorderLayout.CENTER);
        
        JPanel inputPanel = new JPanel(new BorderLayout(5, 0));
        inputPanel.setBackground(new Color(240, 248, 255));
        
        messageField = new JTextField();
        messageField.setFont(new Font("Arial", Font.PLAIN, 14));
        messageField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(70, 130, 180), 1),
            BorderFactory.createEmptyBorder(5, 5, 5, 5)
        ));
        sendMessageButton = new JButton("Send");
        sendMessageButton.setBackground(new Color(70, 130, 180));
        sendMessageButton.setForeground(Color.WHITE);
        sendMessageButton.setFocusPainted(false);
        sendMessageButton.setBorderPainted(false);
        sendMessageButton.setOpaque(true);
        
        inputPanel.add(messageField, BorderLayout.CENTER);
        inputPanel.add(sendMessageButton, BorderLayout.EAST);
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.setBackground(new Color(240, 248, 255));
        
        backToTransferButton = new JButton("Back to Transfer");
        backToTransferButton.setBackground(new Color(70, 130, 180));
        backToTransferButton.setForeground(Color.WHITE);
        backToTransferButton.setFocusPainted(false);
        backToTransferButton.setBorderPainted(false);
        backToTransferButton.setOpaque(true);
        
        buttonPanel.add(backToTransferButton);
        
        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.setBackground(new Color(240, 248, 255));
        bottomPanel.add(inputPanel, BorderLayout.CENTER);
        bottomPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        chatPanel.add(bottomPanel, BorderLayout.SOUTH);
        sendMessageButton.addActionListener(e -> sendChatMessage());
        messageField.addActionListener(e -> sendChatMessage());
        backToTransferButton.addActionListener(e -> cardLayout.show(mainPanel, TRANSFER_PANEL));
        
        mainPanel.add(chatPanel, CHAT_PANEL);
        chatArea.setText("SecureBot: Hello! I'm your secure file transfer assistant.\n" +
                         "How can I help you today?\n\n");
    }
    private void loadUserDatabase() {
        File dbFile = new File(USER_DATABASE_FILE);
        try {
            if (dbFile.exists()) {
                try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(dbFile))) {
                    userDatabase = (Map<String, User>) in.readObject();
                    System.out.println("Loaded user database with " + userDatabase.size() + " users");
                } catch (Exception e) {
                    System.err.println("Failed to load user database: " + e.getMessage());
                    e.printStackTrace();
                    userDatabase = new HashMap<>();
                    userDatabase.put("admin", new User("admin", "admin123", "admin"));
                }
            } else {
                System.out.println("User database file does not exist. Creating with default users.");
                userDatabase = new HashMap<>();
                userDatabase.put("admin", new User("admin", "admin123", "admin"));
                saveUserDatabase();
            }
        } catch (Exception e) {
            System.err.println("Critical error with user database: " + e.getMessage());
            e.printStackTrace();
            userDatabase = new HashMap<>();
            userDatabase.put("admin", new User("admin", "admin123", "admin"));
        }
    }
    private void saveUserDatabase() {
        try {
            File dbFile = new File(USER_DATABASE_FILE);
            File parentDir = dbFile.getParentFile();
            if (parentDir != null && !parentDir.exists()) {
                parentDir.mkdirs();
            }
            try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(dbFile))) {
                out.writeObject(userDatabase);
                System.out.println("Saved user database with " + userDatabase.size() + " users");
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("Failed to save user database: " + e.getMessage());
            JOptionPane.showMessageDialog(this, 
                "Failed to save user information: " + e.getMessage(), 
                "Database Error", 
                JOptionPane.ERROR_MESSAGE);
        }
    }
    private void handleLogin() {
        String username = usernameField.getText().trim();
        String password = new String(passwordField.getPassword());
        
        if (username.isEmpty() || password.isEmpty()) {
            JOptionPane.showMessageDialog(this, 
                "Username and password cannot be empty", 
                "Login Error", 
                JOptionPane.ERROR_MESSAGE);
            return;
        }
        User user = userDatabase.get(username);
        if (user != null && user.password.equals(password)) {
            this.username = username;
            logAccess(username, "Login successful");
            cardLayout.show(mainPanel, TRANSFER_PANEL);
            statusArea.setText("Welcome, " + username + "! Please select a file and cover image to transfer.");
            progressBar.setValue(0);
            if ("admin".equals(user.role)) {
                appendStatus("");
                viewLogsButton.setVisible(true);
            } else {
                appendStatus("");
                viewLogsButton.setVisible(false);
            }
            deleteKeysLogsButton.setVisible(true);
            appendStatus("Logged in as " + username + ", role: " + user.role);
        } else {
            JOptionPane.showMessageDialog(this, 
                "Invalid username or password", 
                "Login Error", 
                JOptionPane.ERROR_MESSAGE);
        }
    }
    private void handleRegister() {
        String username = usernameField.getText().trim();
        String password = new String(passwordField.getPassword());
        
        if (username.isEmpty() || password.isEmpty()) {
            JOptionPane.showMessageDialog(this, 
                "Username and password cannot be empty", 
                "Registration Error", 
                JOptionPane.ERROR_MESSAGE);
            return;
        }
        if (username.length() < 3) {
            JOptionPane.showMessageDialog(this,
                "Username must be at least 3 characters long",
                "Registration Error",
                JOptionPane.ERROR_MESSAGE);
            return;
        }
        if (password.length() < 6) {
            JOptionPane.showMessageDialog(this,
                "Password must be at least 6 characters long",
                "Registration Error",
                JOptionPane.ERROR_MESSAGE);
            return;
        }
        if (userDatabase.containsKey(username)) {
            JOptionPane.showMessageDialog(this, 
                "Username already exists. Please choose a different username.", 
                "Registration Error", 
                JOptionPane.ERROR_MESSAGE);
            return;
        }
        userDatabase.put(username, new User(username, password, "user"));
        saveUserDatabase();
        JOptionPane.showMessageDialog(this, 
            "Registration successful! You can now login.", 
            "Registration Success", 
            JOptionPane.INFORMATION_MESSAGE);
    }
    private void chooseFile() {
        JFileChooser chooser = new JFileChooser();
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            selectedFile = chooser.getSelectedFile();
            filePathField.setText(selectedFile.getAbsolutePath());
            statusArea.setText("Selected file: " + selectedFile.getName() + "\n");
            statusArea.append("File size: " + selectedFile.length() + " bytes\n");
            statusArea.append("File type: " + getFileType(selectedFile) + "\n");
            statusArea.append("Please select a cover image if using steganography for key embedding.\n");
        }
    }
    private void chooseCoverImage() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("PNG Images", "png"));
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            selectedCoverImage = chooser.getSelectedFile();
            coverImagePathField.setText(selectedCoverImage.getAbsolutePath());
            statusArea.append("Selected cover image: " + selectedCoverImage.getName() + "\n");
            statusArea.append("Ready to encrypt and send.\n");
        }
    }
    private String getFileType(File file) {
        String name = file.getName().toLowerCase();
        if (name.endsWith(".jpg") || name.endsWith(".jpeg") || name.endsWith(".png") || 
            name.endsWith(".gif") || name.endsWith(".bmp")) {
            return "Image File";
        } else if (name.endsWith(".pdf")) {
            return "PDF Document";
        } else if (name.endsWith(".doc") || name.endsWith(".docx")) {
            return "Word Document";
        } else if (name.endsWith(".txt")) {
            return "Text File";
        } else if (name.endsWith(".mp3") || name.endsWith(".wav") || name.endsWith(".ogg")) {
            return "Audio File";
        } else if (name.endsWith(".mp4") || name.endsWith(".avi") || name.endsWith(".mov") || name.endsWith(".mkv")) {
            return "Video File";
        } else {
            return "Binary File";
        }
    }
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    private String computeHash(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data);
        return bytesToHex(hash);
    }
    private void sendFileToServer() {
        if (selectedFile == null) {
            JOptionPane.showMessageDialog(this, 
                "Please select a file first.", 
                "Error", 
                JOptionPane.ERROR_MESSAGE);
            return;
        }
        boolean useSteganography = keyHandlingCombo.getSelectedItem().equals("Steganography (Key in Image)");
        if (useSteganography && selectedCoverImage == null) {
            JOptionPane.showMessageDialog(this, 
                "Please select a cover image for key embedding (required for steganography).", 
                "Error", 
                JOptionPane.ERROR_MESSAGE);
            return;
        }
        JFileChooser saveChooser = new JFileChooser();
        saveChooser.setDialogTitle("Save Encrypted File");
        saveChooser.setSelectedFile(new File(selectedFile.getName() + ".encrypted"));
        if (saveChooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File encryptedFile = saveChooser.getSelectedFile();
        final File keyFile;
        final File stegoImage;

        File parentDir = encryptedFile.getParentFile();
        try {
            if (!parentDir.exists() && !parentDir.mkdirs()) {
                throw new IOException("Failed to create directory: " + parentDir.getAbsolutePath());
            }
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, 
                "Error creating output directory: " + e.getMessage(), 
                "Error", 
                JOptionPane.ERROR_MESSAGE);
            return;
        }
        if (useSteganography) {
            stegoImage = new File(encryptedFile.getAbsolutePath() + ".stego.png");
            keyFile = null;
            statusArea.append("Debug: Stego-image path set to: " + stegoImage.getAbsolutePath() + "\n");
        } else {
            keyFile = new File(encryptedFile.getAbsolutePath() + ".key");
            stegoImage = null;
            statusArea.append("Debug: Key file path set to: " + keyFile.getAbsolutePath() + "\n");
        }
        new Thread(() -> {
            try {
                SwingUtilities.invokeLater(() -> {
                    encryptSendButton.setEnabled(false);
                    statusArea.append("\nGenerating encryption key...\n");
                    progressBar.setValue(5);
                    progressBar.setString("5%");
                });
                SecretKey encryptionKey = generateKey(getSelectedAlgorithm());
                SwingUtilities.invokeLater(() -> {
                    statusArea.append("Encrypting file locally...\n");
                    progressBar.setValue(20);
                    progressBar.setString("20%");
                });
                encryptFile(selectedFile, encryptedFile, encryptionKey);
                logAccess(username, "Encrypted file: " + selectedFile.getName() + " using " + getSelectedAlgorithm());

                SwingUtilities.invokeLater(() -> {
                    statusArea.append("Local encryption complete!\n");
                    statusArea.append("Verifying encrypted file before signing...\n");
                    progressBar.setValue(25);
                    progressBar.setString("25%");
                });

                Thread.sleep(500);
                if (!encryptedFile.exists() || encryptedFile.length() == 0) {
                    throw new IOException("Encrypted file is empty or not found: " + encryptedFile.getAbsolutePath());
                }
                appendStatus("Encrypted file verified, size: " + encryptedFile.length() + " bytes");

                File signatureFile = new File(encryptedFile.getAbsolutePath() + ".sig");
                byte[] signature = generateDigitalSignature(encryptedFile);
                appendStatus("Writing signature to: " + signatureFile.getAbsolutePath());
                Files.write(signatureFile.toPath(), signature);
                appendStatus("Signature written, size: " + signatureFile.length() + " bytes");

                byte[] writtenSignature = Files.readAllBytes(signatureFile.toPath());
                if (!Arrays.equals(signature, writtenSignature)) {
                    throw new IOException("Signature file write verification failed: written data does not match generated signature");
                }
                appendStatus("Signature file write verified successfully");
                String signatureHashBefore = computeHash(signature);
                appendStatus("Signature hash before sending: " + signatureHashBefore);
                appendStatus("Signature (hex): " + bytesToHex(signature));

                SwingUtilities.invokeLater(() -> {
                    statusArea.append("Digital signature saved to: " + signatureFile.getAbsolutePath() + "\n");
                    if (useSteganography) {
                        statusArea.append("Embedding key in cover image...\n");
                    } else {
                        statusArea.append("Saving key to file...\n");
                    }
                    progressBar.setValue(30);
                    progressBar.setString("30%");
                });
                String keyData = Base64.getEncoder().encodeToString(encryptionKey.getEncoded()) + ":" + encryptionKey.getAlgorithm();
                if (useSteganography) {
                    BufferedImage coverImage = ImageIO.read(selectedCoverImage);
                    BufferedImage stegoImageData = ClientNetworkUtil.embedKeyInImage(coverImage, keyData);
                    ImageIO.write(stegoImageData, "PNG", stegoImage);
                } else {
                    Files.write(keyFile.toPath(), keyData.getBytes());
                }
                SwingUtilities.invokeLater(() -> {
                    if (useSteganography) {
                        statusArea.append("Key embedded in stego-image: " + stegoImage.getAbsolutePath() + "\n");
                    } else {
                        statusArea.append("Key saved to file: " + keyFile.getAbsolutePath() + "\n");
                    }
                    statusArea.append("Performing key exchange with server...\n");
                    progressBar.setValue(40);
                    progressBar.setString("40%");
                });
                SecretKey sharedKey = ClientNetworkUtil.sendFileToServer(encryptedFile, useSteganography ? stegoImage : keyFile, useSteganography, "127.0.0.1", 5000, getSelectedAlgorithm(), rsaKeyPair.getPublic());

                byte[] receivedSignature = Files.readAllBytes(signatureFile.toPath());
                String signatureHashAfter = computeHash(receivedSignature);
                appendStatus("Signature hash after receiving: " + signatureHashAfter);
                appendStatus("Received signature (hex): " + bytesToHex(receivedSignature));
                if (!signatureHashBefore.equals(signatureHashAfter)) {
                    throw new IOException("Signature file corrupted during server transfer: hash mismatch");
                }
                SwingUtilities.invokeLater(() -> {
                    statusArea.append("Encrypted file, signature, and " + (useSteganography ? "stego-image" : "key file") + " sent to server at 127.0.0.1:5000\n");
                    statusArea.append("Shared key established securely.\n");
                    try {
                        String sharedKeyData = Base64.getEncoder().encodeToString(sharedKey.getEncoded()) + ":" + sharedKey.getAlgorithm();
                        if (useSteganography) {
                            File sharedStegoImage = new File(encryptedFile.getAbsolutePath() + ".server.stego.png");
                            BufferedImage sharedCoverImage = ImageIO.read(selectedCoverImage);
                            BufferedImage sharedStegoImageData = ClientNetworkUtil.embedKeyInImage(sharedCoverImage, sharedKeyData);
                            ImageIO.write(sharedStegoImageData, "PNG", sharedStegoImage);
                            statusArea.append("Server key embedded in stego-image: " + sharedStegoImage.getAbsolutePath() + "\n");
                        } else {
                            File sharedKeyFile = new File(encryptedFile.getAbsolutePath() + ".server.key");
                            Files.write(sharedKeyFile.toPath(), sharedKeyData.getBytes());
                            statusArea.append("Server key saved to file: " + sharedKeyFile.getAbsolutePath() + "\n");
                        }
                    } catch (Exception ex) {
                        statusArea.append("Failed to save server key: " + ex.getMessage() + "\n");
                    }
                    JOptionPane.showMessageDialog(this, 
                        "File, signature, and " + (useSteganography ? "stego-image" : "key file") + " sent to server successfully!",
                        "Transfer Complete", 
                        JOptionPane.INFORMATION_MESSAGE);
                    progressBar.setValue(100);
                    progressBar.setString("100%");
                    encryptSendButton.setEnabled(true);
                });
            } catch (ConnectException e) {
                e.printStackTrace();
                SwingUtilities.invokeLater(() -> {
                    statusArea.append("Connection Error: Failed to connect to server at 127.0.0.1:5000. Ensure the server is running.\n");
                    JOptionPane.showMessageDialog(EnhancedSecureFileTransferApp.this, 
                        "Failed to connect to server: " + e.getMessage() + "\nEnsure the server is running on port 5000.", 
                        "Connection Error", 
                        JOptionPane.ERROR_MESSAGE);
                    encryptSendButton.setEnabled(true);
                    progressBar.setValue(0);
                    progressBar.setString("0%");
                });
            } catch (Exception e) {
                e.printStackTrace();
                SwingUtilities.invokeLater(() -> {
                    statusArea.append("Error: " + e.getMessage() + "\n");
                    JOptionPane.showMessageDialog(EnhancedSecureFileTransferApp.this, 
                        "Encryption, signing, or transfer failed: " + e.getMessage(), 
                        "Error", 
                        JOptionPane.ERROR_MESSAGE);
                    encryptSendButton.setEnabled(true);
                    progressBar.setValue(0);
                    progressBar.setString("0%");
                });
            }
        }).start();
    }
    private byte[] generateDigitalSignature(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[4096];
        long totalBytesRead = 0;
        long fileSize = file.length();
        appendStatus("Generating signature for file: " + file.getAbsolutePath() + ", size: " + fileSize + " bytes");
        try (FileInputStream fis = new FileInputStream(file)) {
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
                totalBytesRead += bytesRead;
            }
        }
        if (totalBytesRead != fileSize) {
            throw new IOException("Incomplete read during signature generation: expected " + fileSize + " bytes, read " + totalBytesRead + " bytes");
        }
        byte[] hash = digest.digest();
        appendStatus("Hash during signature generation: " + Base64.getEncoder().encodeToString(hash));

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "SunJCE");
        cipher.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPrivate());
        byte[] signature = cipher.doFinal(hash);
        appendStatus("Generated signature, length: " + signature.length + " bytes, content (hex): " + bytesToHex(signature));
        return signature;
    }
    private boolean verifyDigitalSignature(File file, File signatureFile) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[4096];
        long totalBytesRead = 0;
        long fileSize = file.length();
        appendStatus("Verifying signature for file: " + file.getAbsolutePath() + ", size: " + fileSize + " bytes");
        try (FileInputStream fis = new FileInputStream(file)) {
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
                totalBytesRead += bytesRead;
            }
        }
        if (totalBytesRead != fileSize) {
            throw new IOException("Incomplete read of encrypted file: expected " + fileSize + " bytes, read " + totalBytesRead + " bytes");
        }
        byte[] computedHash = digest.digest();
        appendStatus("Computed hash of encrypted file: " + Base64.getEncoder().encodeToString(computedHash));

        byte[] signature = Files.readAllBytes(signatureFile.toPath());
        appendStatus("Signature loaded, length: " + signature.length + " bytes, content (hex): " + bytesToHex(signature));

        if (signature.length != 256) {
            throw new Exception("Invalid signature length: expected 256 bytes, got " + signature.length + " bytes. Signature (hex): " + bytesToHex(signature));
        }

        if (rsaKeyPair == null || rsaKeyPair.getPublic() == null) {
            throw new IllegalStateException("RSA public key not loaded");
        }
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "SunJCE");
        cipher.init(Cipher.DECRYPT_MODE, rsaKeyPair.getPublic());
        byte[] decryptedHash = cipher.doFinal(signature);
        appendStatus("Decrypted hash from signature: " + Base64.getEncoder().encodeToString(decryptedHash));

        boolean isValid = MessageDigest.isEqual(computedHash, decryptedHash);
        appendStatus("Signature verification " + (isValid ? "succeeded" : "failed"));
        return isValid;
    }
    private void receiveFile() {
        JFileChooser encryptedFileChooser = new JFileChooser();
        encryptedFileChooser.setDialogTitle("Select Encrypted File");
        if (encryptedFileChooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File encryptedFile = encryptedFileChooser.getSelectedFile();

        JFileChooser signatureFileChooser = new JFileChooser();
        signatureFileChooser.setDialogTitle("Select Signature File");
        signatureFileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("Signature Files", "sig"));
        if (signatureFileChooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File signatureFile = signatureFileChooser.getSelectedFile();

        int skipSignatureChoice = JOptionPane.showConfirmDialog(this,
            "Would you like to skip signature verification (for debugging only)?",
            "Skip Signature Verification",
            JOptionPane.YES_NO_OPTION);
        boolean skipSignatureVerification = (skipSignatureChoice == JOptionPane.YES_OPTION);

        String[] options = {"Key File", "Steganography (Key in Image)"};
        int choice = JOptionPane.showOptionDialog(this,
            "How was the key stored during encryption?",
            "Select Key Retrieval Method",
            JOptionPane.DEFAULT_OPTION,
            JOptionPane.QUESTION_MESSAGE,
            null,
            options,
            options[0]);

        if (choice == -1) {
            return;
        }
        boolean useSteganography = (choice == 1);
        File keyFile = null;
        File stegoImage = null;

        if (useSteganography) {
            JFileChooser stegoImageChooser = new JFileChooser();
            stegoImageChooser.setDialogTitle("Select Stego-Image");
            stegoImageChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("PNG Images", "png"));
            if (stegoImageChooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
                return;
            }
            stegoImage = stegoImageChooser.getSelectedFile();
            statusArea.append("Debug: Stego-image selected: " + stegoImage.getAbsolutePath() + "\n");
        } else {
            JFileChooser keyFileChooser = new JFileChooser();
            keyFileChooser.setDialogTitle("Select Key File");
            keyFileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("Key Files", "key"));
            if (keyFileChooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
                return;
            }
            keyFile = keyFileChooser.getSelectedFile();
            statusArea.append("Debug: Key file selected: " + keyFile.getAbsolutePath() + "\n");
        }
        JFileChooser saveChooser = new JFileChooser();
        saveChooser.setDialogTitle("Save Decrypted File");
        String originalName = encryptedFile.getName();
        if (originalName.toLowerCase().endsWith(".encrypted")) {
            originalName = originalName.substring(0, originalName.length() - 10);
        }
        saveChooser.setSelectedFile(new File(originalName));
        if (saveChooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File decryptedFile = saveChooser.getSelectedFile();

        final File finalKeyFile = keyFile;
        final File finalStegoImage = stegoImage;

        new Thread(() -> {
            try {
                SwingUtilities.invokeLater(() -> {
                    decryptReceiveButton.setEnabled(false);
                    statusArea.append("\nVerifying digital signature...\n");
                    progressBar.setValue(5);
                    progressBar.setString("5%");
                });

                boolean isSignatureValid = false;
                if (!skipSignatureVerification) {
                    isSignatureValid = verifyDigitalSignature(encryptedFile, signatureFile);
                    if (!isSignatureValid) {
                        throw new SecurityException("Digital signature verification failed. File may be tampered or keys may not match.");
                    }
                } else {
                    SwingUtilities.invokeLater(() -> {
                        statusArea.append("Warning: Skipped signature verification (debug mode).\n");
                    });
                }

                SwingUtilities.invokeLater(() -> {
                    if (!skipSignatureVerification) {
                        statusArea.append("Digital signature verified successfully.\n");
                    }
                    statusArea.append("Extracting key " + (useSteganography ? "from stego-image" : "from key file") + "...\n");
                    progressBar.setValue(10);
                    progressBar.setString("10%");
                });

                String keyData;
                if (useSteganography) {
                    BufferedImage stegoImageData = ImageIO.read(finalStegoImage);
                    keyData = ClientNetworkUtil.extractKeyFromImage(stegoImageData);
                } else {
                    keyData = new String(Files.readAllBytes(finalKeyFile.toPath()));
                }
                appendStatus("Key data extracted: " + keyData);

                String[] keyParts = keyData.split(":");
                if (keyParts.length != 2) {
                    throw new Exception("Invalid key format in " + (useSteganography ? "stego-image" : "key file") + ": expected format 'key:algorithm'");
                }
                byte[] keyBytes;
                try {
                    keyBytes = Base64.getDecoder().decode(keyParts[0]);
                } catch (IllegalArgumentException e) {
                    throw new Exception("Failed to decode key: " + e.getMessage());
                }
                String algorithm = keyParts[1];
                appendStatus("Decoded key length: " + keyBytes.length + " bytes, algorithm: " + algorithm);
                SecretKey decryptionKey = new SecretKeySpec(keyBytes, algorithm);

                SwingUtilities.invokeLater(() -> {
                    statusArea.append("Decrypting file...\n");
                    progressBar.setValue(30);
                    progressBar.setString("30%");
                });
                decryptFile(encryptedFile, decryptedFile, decryptionKey);
                logAccess(username, "Decrypted file: " + decryptedFile.getName() + " using " + getSelectedAlgorithm());

                SwingUtilities.invokeLater(() -> {
                    statusArea.append("Decryption complete!\n");
                    statusArea.append("Decrypted file saved to: " + decryptedFile.getAbsolutePath() + "\n");
                    progressBar.setValue(100);
                    progressBar.setString("100%");
                    decryptReceiveButton.setEnabled(true);
                });
            } catch (Exception e) {
                e.printStackTrace();
                SwingUtilities.invokeLater(() -> {
                    statusArea.append("Error: " + e.getMessage() + "\n");
                    JOptionPane.showMessageDialog(EnhancedSecureFileTransferApp.this, 
                        "Decryption or signature verification failed: " + e.getMessage(), 
                        "Decryption Error", 
                        JOptionPane.ERROR_MESSAGE);
                    decryptReceiveButton.setEnabled(true);
                    progressBar.setValue(0);
                    progressBar.setString("0%");
                });
            }
        }).start();
    }
    private String getSelectedAlgorithm() {
        String selected = (String) algorithmCombo.getSelectedItem();
        if (selected.equals("AES")) {
            return AES_ALGO;
        } else if (selected.equals("Blowfish")) {
            return BLOWFISH_ALGO;
        } else {
            return "DOUBLE";
        }
    }
    private SecretKey generateKey(String algorithm) throws Exception {
        if ("DOUBLE".equals(algorithm)) {
            KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGO);
            SecureRandom secRandom = new SecureRandom();
            keyGen.init(256, secRandom);
            SecretKey aesKey = keyGen.generateKey();
            appendStatus("Generated AES key for double encryption, length: " + aesKey.getEncoded().length + " bytes");
            return aesKey;
        }
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
        SecureRandom secRandom = new SecureRandom();
        keyGen.init(algorithm.equals(AES_ALGO) ? 256 : 448, secRandom);
        SecretKey key = keyGen.generateKey();
        appendStatus("Generated " + algorithm + " key, length: " + key.getEncoded().length + " bytes");
        return key;
    }
    private void encryptFile(File inputFile, File outputFile, SecretKey key) throws Exception {
        String algorithm = getSelectedAlgorithm();
        appendStatus("Starting encryption of file: " + inputFile.getAbsolutePath() + " using " + algorithm);
        appendStatus("Input file size: " + inputFile.length() + " bytes");
        
        byte[] inputBytes;
        try (FileInputStream inputStream = new FileInputStream(inputFile)) {
            inputBytes = new byte[(int) inputFile.length()];
            int bytesRead = inputStream.read(inputBytes);
            if (bytesRead != inputFile.length()) {
                throw new IOException("Incomplete read of input file: expected " + inputFile.length() + " bytes, read " + bytesRead + " bytes");
            }
        }
        appendStatus("Successfully read " + inputBytes.length + " bytes from input file");

        byte[] outputBytes;
        SecretKey finalKey = key;

        if ("DOUBLE".equals(algorithm)) {
            appendStatus("Performing AES encryption...");
            Cipher aesCipher = Cipher.getInstance(AES_ALGO);
            aesCipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] aesEncrypted = aesCipher.doFinal(inputBytes);
            appendStatus("AES encryption complete, size: " + aesEncrypted.length + " bytes");

            appendStatus("Applying wavelet transform...");
            byte[] waveletTransformed = applyWaveletTransform(aesEncrypted);
            appendStatus("Wavelet transform complete, size: " + waveletTransformed.length + " bytes");

            appendStatus("Generating Blowfish key...");
            KeyGenerator blowfishKeyGen = KeyGenerator.getInstance(BLOWFISH_ALGO);
            blowfishKeyGen.init(448, new SecureRandom());
            SecretKey blowfishKey = blowfishKeyGen.generateKey();
            appendStatus("Blowfish key generated, length: " + blowfishKey.getEncoded().length + " bytes");

            appendStatus("Performing Blowfish encryption...");
            Cipher blowfishCipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
            blowfishCipher.init(Cipher.ENCRYPT_MODE, blowfishKey);
            outputBytes = blowfishCipher.doFinal(waveletTransformed);
            appendStatus("Blowfish encryption complete, size: " + outputBytes.length + " bytes");

            ByteArrayOutputStream combinedKeyStream = new ByteArrayOutputStream();
            combinedKeyStream.write(key.getEncoded());
            combinedKeyStream.write(blowfishKey.getEncoded());
            finalKey = new SecretKeySpec(combinedKeyStream.toByteArray(), "COMBINED");
            appendStatus("Combined key created for double encryption, length: " + finalKey.getEncoded().length + " bytes");
        } else {
            appendStatus("Performing " + algorithm + " encryption...");
            String transformation = algorithm.equals(BLOWFISH_ALGO) ? "Blowfish/ECB/PKCS5Padding" : algorithm;
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            outputBytes = cipher.doFinal(inputBytes);
            appendStatus(algorithm + " encryption complete, size: " + outputBytes.length + " bytes");
        }
        try (FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            outputStream.write(outputBytes);
            outputStream.flush();
        }
        appendStatus("Encrypted file written to: " + outputFile.getAbsolutePath() + ", size: " + outputFile.length() + " bytes");

        byte[] writtenBytes;
        try (FileInputStream verifyStream = new FileInputStream(outputFile)) {
            writtenBytes = new byte[(int) outputFile.length()];
            int bytesRead = verifyStream.read(writtenBytes);
            if (bytesRead != outputFile.length()) {
                throw new IOException("Incomplete read of encrypted file during verification: expected " + outputFile.length() + " bytes, read " + bytesRead + " bytes");
            }
        }
        if (!Arrays.equals(outputBytes, writtenBytes)) {
            throw new IOException("Encrypted file write verification failed: written data does not match encrypted data");
        }
        appendStatus("Encrypted file write verified successfully");

        try {
            java.lang.reflect.Field keyField = this.getClass().getDeclaredField("sendFileToServer$encryptionKey");
            keyField.setAccessible(true);
            keyField.set(this, finalKey);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            appendStatus("" + e.getMessage());
        }
        for (int i = 20; i <= 90; i += 10) {
            final int progress = i;
            SwingUtilities.invokeLater(() -> {
                progressBar.setValue(progress);
                progressBar.setString(progress + "%");
            });
            try {
                Thread.sleep(100);
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
            }
        }
    }
    private byte[] applyWaveletTransform(byte[] data) {
        int len = data.length;
        byte[] result = new byte[len];
        int processLength = (len % 2 == 0) ? len : len - 1;
        for (int i = 0; i < processLength; i += 2) {

            short sum = (short) ((data[i] & 0xFF) + (data[i + 1] & 0xFF));
            short avg = (short) (sum / 2);
            short diff = (short) ((data[i] & 0xFF) - (data[i + 1] & 0xFF));
            result[i / 2] = (byte) avg;
            result[len / 2 + i / 2] = (byte) diff;
        }
        if (len % 2 != 0) {
            result[len - 1] = data[len - 1];
        }
        return result;
    }
    private byte[] inverseWaveletTransform(byte[] data) {
        int len = data.length;
        byte[] result = new byte[len];
        int halfSize = len / 2;
        for (int i = 0; i < halfSize; i++) {
            short avg = (short) (data[i] & 0xFF);
            short diff = (short) (data[halfSize + i] & 0xFF);
            short val1 = (short) (avg + (diff / 2));
            short val2 = (short) (avg - (diff / 2));
          
            result[2 * i] = (byte) (val1 & 0xFF);
            result[2 * i + 1] = (byte) (val2 & 0xFF);
        }
        if (len % 2 != 0) {
            result[len - 1] = data[len - 1];
        }
        return result;
    }
    private void decryptFile(File inputFile, File outputFile, SecretKey key) throws Exception {
        appendStatus("Starting decryption of file: " + inputFile.getAbsolutePath());
        appendStatus("Input file size: " + inputFile.length() + " bytes");
        
        try (FileInputStream inputStream = new FileInputStream(inputFile);
             FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            
            byte[] inputBytes = new byte[(int) inputFile.length()];
            int bytesRead = inputStream.read(inputBytes);
            if (bytesRead != inputFile.length()) {
                throw new IOException("Incomplete read of encrypted file: expected " + inputFile.length() + " bytes, read " + bytesRead + " bytes");
            }
            appendStatus("Successfully read " + inputBytes.length + " bytes from encrypted file");

            byte[] outputBytes;
            String algorithm = key.getAlgorithm();
            appendStatus("Decryption algorithm: " + algorithm + ", key length: " + key.getEncoded().length + " bytes");

            if ("COMBINED".equals(algorithm)) {
                byte[] combinedKey = key.getEncoded();
                appendStatus("Combined key length: " + combinedKey.length + " bytes");

                if (combinedKey.length < 88) {
                    throw new IllegalArgumentException("Combined key length too short: expected at least 88 bytes, got " + combinedKey.length);
                }
                byte[] aesKeyBytes = new byte[32];
                byte[] blowfishKeyBytes = new byte[56];
                System.arraycopy(combinedKey, 0, aesKeyBytes, 0, 32);
                System.arraycopy(combinedKey, 32, blowfishKeyBytes, 0, 56);
                
                SecretKey aesKey = new SecretKeySpec(aesKeyBytes, AES_ALGO);
                SecretKey blowfishKey = new SecretKeySpec(blowfishKeyBytes, BLOWFISH_ALGO);
                appendStatus("Split keys - AES key length: " + aesKey.getEncoded().length + " bytes, Blowfish key length: " + blowfishKey.getEncoded().length + " bytes");

                appendStatus("Performing Blowfish decryption...");
                Cipher blowfishCipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
                blowfishCipher.init(Cipher.DECRYPT_MODE, blowfishKey);
                byte[] blowfishDecrypted = blowfishCipher.doFinal(inputBytes);
                appendStatus("Blowfish decryption complete, size: " + blowfishDecrypted.length + " bytes");

                appendStatus("Applying inverse wavelet transform...");
                byte[] waveletDecrypted = inverseWaveletTransform(blowfishDecrypted);
                appendStatus("Inverse wavelet transform complete, size: " + waveletDecrypted.length + " bytes");

                appendStatus("Performing AES decryption...");
                Cipher aesCipher = Cipher.getInstance(AES_ALGO);
                aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
                outputBytes = aesCipher.doFinal(waveletDecrypted);
                appendStatus("AES decryption complete, size: " + outputBytes.length + " bytes");
            } else {
                appendStatus("Performing " + algorithm + " decryption...");
                String transformation = algorithm.equals(BLOWFISH_ALGO) ? "Blowfish/ECB/PKCS5Padding" : algorithm;
                Cipher cipher = Cipher.getInstance(transformation);
                cipher.init(Cipher.DECRYPT_MODE, key);
                outputBytes = cipher.doFinal(inputBytes);
                appendStatus(algorithm + " decryption complete, size: " + outputBytes.length + " bytes");
            }
            outputStream.write(outputBytes);
            outputStream.flush();
            appendStatus("Decrypted file written to: " + outputFile.getAbsolutePath() + ", size: " + outputFile.length() + " bytes");

            byte[] writtenBytes;
            try (FileInputStream verifyStream = new FileInputStream(outputFile)) {
                writtenBytes = new byte[(int) outputFile.length()];
                bytesRead = verifyStream.read(writtenBytes);
                if (bytesRead != outputFile.length()) {
                    throw new IOException("Incomplete read of decrypted file during verification: expected " + outputFile.length() + " bytes, read " + bytesRead + " bytes");
                }
            }
            if (!Arrays.equals(outputBytes, writtenBytes)) {
                throw new IOException("Decrypted file write verification failed: written data does not match decrypted data");
            }
            appendStatus("Decrypted file write verified successfully");

            for (int i = 30; i <= 90; i += 10) {
                final int progress = i;
                SwingUtilities.invokeLater(() -> {
                    progressBar.setValue(progress);
                    progressBar.setString(progress + "%");
                });
                try {
                    Thread.sleep(100);
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                }
            }
        } catch (Exception e) {
            appendStatus("Decryption failed: " + e.getMessage());
            throw e;
        }
    }
    private void logout() {
        logAccess(username, "User logged out");
        username = "";
        cardLayout.show(mainPanel, LOGIN_PANEL);
        usernameField.setText("");
        passwordField.setText("");
        selectedFile = null;
        selectedCoverImage = null;
        filePathField.setText("");
        coverImagePathField.setText("");
    }
    private void showChatPanel() {
        cardLayout.show(mainPanel, CHAT_PANEL);
    }
    private void sendChatMessage() {
        String message = messageField.getText().trim();
        if (!message.isEmpty()) {
            chatArea.append("You: " + message + "\n\n");
            messageField.setText("");
            chatHistory.add("You: " + message);
            processAndRespondToMessage(message);
        }
    }
    private void processAndRespondToMessage(String message) {
        new Thread(() -> {
            try {
                Thread.sleep(800);
                String response = generateChatbotResponse(message);
                SwingUtilities.invokeLater(() -> {
                    chatArea.append("SecureBot: " + response + "\n\n");
                    chatHistory.add("SecureBot: " + response);
                    chatArea.setCaretPosition(chatArea.getDocument().getLength());
                    chatbotAvatar.repaint();
                });
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
    }
    private String generateChatbotResponse(String message) {
        message = message.toLowerCase();
        if (message.contains("aes")) {
            return "AES (Advanced Encryption Standard) is a symmetric encryption algorithm known for speed and security. It's widely used in banking, file security, and messaging.";
        } else if (message.contains("blowfish")) {
            return "Blowfish is a symmetric block cipher designed for fast and secure encryption. It's suitable for smaller file encryption and offers flexibility in key size.";
        } else if (message.contains("double") || message.contains("wavelet")) {
            return "Double encryption in this app combines AES and Blowfish, plus a wavelet transform for added data compression and security.";
        } else if (message.contains("enc") || message.contains("how to encrypt") || message.contains("encryption process")) {
            return "To encrypt a file:\n1. Go to the Transfer Panel.\n2. Click 'Browse' to select a file.\n3. Select the encryption algorithm.\n4. Choose key handling (Normal or Steganography). If using steganography, select a cover image.\n5. Click 'Encrypt & Send'.\nThe key is either saved to a file or embedded in a stego-image.";
        } else if (message.contains("dec") || message.contains("how to decrypt")) {
            return "To decrypt a file:\n1. Go to the Transfer Panel.\n2. Click 'Decrypt & Receive'.\n3. Select the encrypted file and signature file.\n4. Choose the key retrieval method (Key File or Steganography).\n5. Select the key file or stego-image.\n6. Choose where to save the output.";
        } else if (message.contains("which algorithm") || message.contains("most secure") || message.contains("best encryption")) {
            return "The most secure option is Double Encryption (AES + Blowfish + Wavelet), offering layered protection. Use it for highly sensitive files.";
        } else if (message.contains("key file") || message.contains("encryption key")) {
            return "The encryption key can be stored in a separate .key file (Normal Encryption) or embedded in a stego-image using steganography. Choose your preferred method in the Transfer Panel.";
        } else if (message.contains("steganography") || message.contains("stego")) {
            return "Steganography hides the encryption key in an image using LSB (Least Significant Bit) techniques. Select a PNG cover image to embed the key securely, or choose Normal Encryption to save the key in a file.";
        } else if (message.contains("hello") || message.contains("hi") || message.contains("hey")) {
            return "Hello! 👋 I'm SecureBot. Ask me anything about file encryption, steganography, or security.";
        } else if (message.contains("thank")) {
            return "You're welcome! 😊 I'm here to help anytime.";
        } else if (message.contains("bye") || message.contains("goodbye")) {
            return "Goodbye! Stay safe and secure your files!";
        } else if (message.contains("secure") || message.contains("security")) {
            return "Security is our priority. Files are encrypted, keys are exchanged via Diffie-Hellman, and keys can be hidden in images using steganography or saved in a separate file.";
        } else if (message.contains("help") || message.contains("assist")) {
            return "I can help you encrypt, decrypt, and understand encryption and steganography. Use the Transfer Panel or ask about key embedding options!";
        } else if (message.contains("file size") || message.contains("limit")) {
            return "The app supports files of any size, but very large files (e.g., >1GB) may take longer to encrypt and transfer due to processing time.";
        } else if (message.contains("signature") || message.contains("digital signature")) {
            return "Digital signatures are used to verify the integrity of the file. They are created using your RSA private key and verified with your public key to ensure the file hasn't been tampered with.";
        } else if (message.contains("delete") || message.contains("delete keys")) {
            return "To delete keys and logs, click the 'Delete Keys & Logs' button in the Transfer Panel. This will remove all .key, .sig, and .stego.png files, as well as the audit log.";
        } else if (message.contains("logs") || message.contains("view logs")) {
            return "Admins can view logs by clicking the 'View Logs' button in the Transfer Panel. Logs show user actions like logins, file encryptions, and decryptions.";
        } else if (message.contains("register") || message.contains("sign up")) {
            return "To register, go to the Login Panel, enter a username (at least 3 characters) and password (at least 6 characters), then click 'Register'. You can then log in with those credentials.";
        } else if (message.contains("error") || message.contains("not working")) {
            return "If you're encountering an error, check the status area in the Transfer Panel for details. Common issues include missing files, server connection problems, or mismatched keys.";
        } else if (message.contains("server") || message.contains("connection")) {
            return "The app connects to a server at 127.0.0.1:5000 for file transfer. Ensure the server is running on this address and port, or you may see a connection error.";
        } else if (message.contains("time") || message.contains("date")) {
            return "I can tell you the current time! It's " + new Date().toString() + ".";
        } else {
            return "I'm not sure how to answer that. Try asking about encryption, steganography, or file transfer processes!";
        }
    }
    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            e.printStackTrace();
        }
        SwingUtilities.invokeLater(() -> {
            EnhancedSecureFileTransferApp app = new EnhancedSecureFileTransferApp();
            app.setVisible(true);
        });
    }
}