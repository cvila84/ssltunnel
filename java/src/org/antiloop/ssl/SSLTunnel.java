package org.antiloop.ssl;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Iterator;
import java.util.NoSuchElementException;

public class SSLTunnel implements Runnable {

    private final byte[] buffer1 = new byte[2048];
    private final byte[] buffer2 = new byte[2048];

    private int listenPort;
    private String proxyHost;
    private int proxyPort;
    private final String remoteHost;
    private final int remotePort;
    private final boolean retry;

    private Socket clientSocket;
    private BufferedInputStream clientIn;
    private BufferedOutputStream clientOut;
    private SSLSocket serverSocket;
    private BufferedOutputStream serverOut;
    private BufferedInputStream serverIn;

    private boolean logFile;
    private String logFileName;
    private PrintWriter log;

    private boolean tcpClient = false;
    private boolean proxy = false;

    private SSLTunnel(String remoteHost, int remotePort, boolean retry) {
        this.remoteHost = remoteHost;
        this.remotePort = remotePort;
        this.retry = retry;
    }

    private void setProxy(String proxyHost, int proxyPort) {
        this.proxy = true;
        this.proxyHost = proxyHost;
        this.proxyPort = proxyPort;
    }

    private void setTCPClient(int listenPort) {
        this.tcpClient = true;
        this.listenPort = listenPort;
    }

    private void setLogFile(String logFileName) {
        this.logFile = true;
        this.logFileName = logFileName;
    }

    @Override
    public void run() {
        int nRead;
        try {
            println("Waiting for incoming message from server...");
            while((nRead = serverIn.read(buffer2, 0, buffer2.length)) != -1) {
                println("Read " + nRead + " byte(s) from server");
                println("Writing " + nRead + " byte(s) to the client");
                clientOut.write(buffer2, 0, nRead);
                clientOut.flush();
            }
            println("Connection closed by server");
        } catch (IOException ex) {
            println("Connection interrupted by server (" + ex + ")");
        }
    }

    private void start() {
        try {
            if(logFile) {
                log = new PrintWriter(logFileName);
            }
        } catch(IOException ex) {
            System.out.println("Warning: cannot create log file " + logFileName);
        }
        try {
            do {
                try {
                    int nRead;
                    setupStreams();
                    setupSSL();
                    new Thread(this).start();
                    println("Waiting for incoming message from client...");
                    while((nRead = clientIn.read(buffer1, 0, buffer1.length)) != -1) {
                        println("Read " + nRead + " byte(s) from client");
                        println("Writing " + nRead + " byte(s) to the server");
                        serverOut.write(buffer1, 0, nRead);
                        serverOut.flush();
                    }
                    println("Connection closed by client");
                    if(tcpClient) {
                        clientOut.close();
                        clientIn.close();
                        clientSocket.close();
                    }
                    serverOut.close();
                    serverIn.close();
                    serverSocket.close();
                } catch(Exception ex) {
                    if(log != null) {
                        ex.printStackTrace(log);
                    } else {
                        ex.printStackTrace();
                    }
                }
            } while(retry);
        } finally {
            if(log != null) {
                log.close();
            }
        }
    }

    private void println(String str) {
        if(log != null) {
            log.println(str);
            log.flush();
        }
    }

    private void setupStreams() throws IOException {
        if(tcpClient) {
            ServerSocket socket = new ServerSocket(listenPort);
            println("Listening on port " + listenPort + "...");
            clientSocket = socket.accept();
            println("Accepted connection from " + clientSocket.getInetAddress().getHostName() + ":" + clientSocket.getPort());
            clientIn = new BufferedInputStream(clientSocket.getInputStream());
            clientOut = new BufferedOutputStream(clientSocket.getOutputStream());
        } else {
            clientIn = new BufferedInputStream(System.in);
            clientOut = new BufferedOutputStream(System.out);
        }
    }

    private void setupSSL() throws IOException, KeyManagementException, NoSuchAlgorithmException {
        if(proxy) {
            println("Creating tunnel with " + proxyHost + ":" + proxyPort + "...");
            Socket proxySocket = createHTTPTunnelSocket(proxyHost, proxyPort, remoteHost, remotePort);
            println("Securing tunnel...");
            serverSocket = secureSocket(proxySocket);
        } else {
            println("Connecting to " + remoteHost + ":" + remotePort + "...");
            Socket directSocket = createDirectSocket(remoteHost, remotePort);
            println("Securing connection...");
            serverSocket = secureSocket(directSocket);
        }
        serverOut = new BufferedOutputStream(serverSocket.getOutputStream());
        serverIn = new BufferedInputStream(serverSocket.getInputStream());
    }

    private SSLSocket secureSocket(Socket tunnelSocket) throws NoSuchAlgorithmException, KeyManagementException, IOException {
        SSLContext sslContext = SSLContext.getInstance("SSL");
        TrustManager[] trustManagers = new TrustManager[] {
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
        };
        sslContext.init(null, trustManagers, null);
        SSLSocket sslSocket = (SSLSocket)(sslContext.getSocketFactory()).createSocket(tunnelSocket, remoteHost, remotePort, true);
        sslSocket.setUseClientMode(true);
        println("Performing SSL handshake...");
        sslSocket.startHandshake();
        return sslSocket;
    }

    private Socket createDirectSocket(String remoteHost, int remotePort) throws IOException {
        return new Socket(remoteHost, remotePort);
    }

    private Socket createHTTPTunnelSocket(String proxyHost, int proxyPort, String remoteHost, int remotePort) throws IOException {
        Socket proxySocket = new Socket(proxyHost, proxyPort);
        OutputStream out = proxySocket.getOutputStream();
        String connect = "CONNECT " + remoteHost + ":" + remotePort + " HTTP/1.1\r\n" +
                "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko\r\n" +
                "Host: " + remoteHost + "\r\n" +
                "Content-Length: 0\r\n" +
                "DNT: 1\r\n" +
                "Proxy-Connection: Keep-Alive\r\n" +
                "Pragma: no-cache\r\n\r\n";
        out.write(connect.getBytes("ASCII7"));
        out.flush();
        InputStream in = proxySocket.getInputStream();
        int nLines = 0;
        int nRead = 0;
        while(nLines < 1 || nRead == buffer1.length) {
            int i = in.read();
            if(i < 0) {
                throw new IOException("Unexpected EOF");
            }
            if(i == '\n') {
                nLines++;
            } else if(nRead < buffer1.length) {
                buffer1[nRead++] = (byte)i;
            }
        }
        while(in.available() > 0) {
            in.read();
        }
        String response = new String(buffer1, 0, nRead, "ASCII7");
        if(!response.startsWith("HTTP/1.1 200")) {
            throw new IOException("HTTP KO");
        }
        return proxySocket;
    }

    private static void usage() {
        System.out.println("Usage: SSLTunnel <inputStream> <remoteHost>:<remotePort> -p <proxyHost>:<proxyPort> -l <fileName>");
        System.out.println("<inputStream> is either - for stdin or tcp:<listenPort> for TCP");
        System.out.println("<remoteHost>:<remotePort> is the remote host to connect to");
        System.out.println("-p <proxyHost>:<proxyPort> creates the tunnel through a HTTP proxy, direct SSL otherwise");
        System.out.println("-l <fileName> writes log in a file, no log written otherwise");
        System.out.println("-r retry in case of connection failure");
    }

    public static void main(String[] args) {
        boolean valid = true;
        boolean stdin = false;
        int tcpListenPort = -1;
        String remoteHost = null;
        int remotePort = -1;
        boolean proxy = false;
        String proxyHost = null;
        int proxyPort = -1;
        boolean logFile = false;
        String logFileName = null;
        boolean retry = false;
        int i = 1;
        if(args.length == 0) {
            usage();
            System.exit(1);
        }
        Iterator<String> it = Arrays.asList(args).iterator();
        try {
            do {
                String arg = it.next();
                if(arg.startsWith("-")) {
                    if(arg.length() == 1) {
                        if(i == 1) {
                            stdin = true;
                            i++;
                        } else {
                            valid = false;
                            break;
                        }
                    } else {
                        if(arg.charAt(1) == 'p') {
                            String proxyAddr = it.next();
                            int j = proxyAddr.indexOf(':');
                            if(j < 1 || j == proxyAddr.length() - 1) {
                                valid = false;
                                break;
                            }
                            proxyHost = proxyAddr.substring(0, j);
                            proxyPort = Integer.parseInt(proxyAddr.substring(j + 1));
                            proxy = true;
                        } else if(arg.charAt(1) == 'l') {
                            logFileName = it.next();
                            logFile = true;
                        } else if(arg.charAt(1) == 'r') {
                            retry = true;
                        } else {
                            valid = false;
                            break;
                        }
                    }
                } else {
                    if(i == 1 && arg.startsWith("tcp:")) {
                        tcpListenPort = Integer.parseInt(arg.substring(4));
                        i++;
                    } else if(i == 2) {
                        int j = arg.indexOf(':');
                        if(j < 1 || j == arg.length() - 1) {
                            valid = false;
                            break;
                        }
                        remoteHost = arg.substring(0, j);
                        remotePort = Integer.parseInt(arg.substring(j + 1));
                        i++;
                    } else {
                        valid = false;
                        break;
                    }
                }
            } while(it.hasNext());
        } catch(NumberFormatException | NoSuchElementException ex) {
            valid = false;
        }
        if(i < 3) {
            valid = false;
        }
        if(!valid) {
            usage();
            System.exit(1);
        }
        SSLTunnel sslTunnel = new SSLTunnel(remoteHost, remotePort, retry);
        if(proxy) {
            sslTunnel.setProxy(proxyHost, proxyPort);
        }
        if(!stdin) {
            sslTunnel.setTCPClient(tcpListenPort);
        }
        if(logFile) {
            sslTunnel.setLogFile(logFileName);
        }
        sslTunnel.start();
    }
}
