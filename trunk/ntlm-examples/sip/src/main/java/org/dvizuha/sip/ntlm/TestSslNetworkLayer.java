/*
 * $Id: $
 */
package org.dvizuha.sip.ntlm;

import gov.nist.core.net.NetworkLayer;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

/**
 * @author <a href="http://profiles.google.com/109977706462274286343">Veritatem Quaeres</a>
 * @version $Revision: $
 */
public class TestSslNetworkLayer implements NetworkLayer {
    /**
     * Creates a server with the specified port, listen backlog,
     * and local IP address to bind to.
     * Comparable to "new java.net.ServerSocket(port,backlog,bindAddress);"
     *
     * @param port the port
     * @param backlog backlog
     * @param bindAddress local address to use
     * @return the newly created server socket.
     * @throws java.io.IOException problem creating socket.
     */
    public ServerSocket createServerSocket(int port, int backlog,
            InetAddress bindAddress)
            throws IOException
    {
        return new ServerSocket(port, backlog, bindAddress);
    }

    /**
     * Creates a stream socket and connects it to the specified
     * port number at the specified IP address.
     *
     * @param address the address to connect.
     * @param port the port to connect.
     * @return the socket
     * @throws IOException problem creating socket.
     */
    public Socket createSocket(InetAddress address, int port)
        throws IOException
    {
        return new Socket(address, port);
    }

    /**
     * Constructs a datagram socket and binds it to any available port on the
     * local host machine.
     * Comparable to "new java.net.DatagramSocket();"
     *
     * @return the datagram socket
     * @throws java.net.SocketException problem creating socket.
     */
    public DatagramSocket createDatagramSocket() throws SocketException {
        return new DatagramSocket();
    }

    /**
     * Creates a datagram socket, bound to the specified local address.
     * Comparable to "new java.net.DatagramSocket(port,laddr);"
     *
     * @param port local port to use
     * @param laddr local address to bind
     * @return the datagram socket
     * @throws SocketException problem creating socket.
     */
    public DatagramSocket createDatagramSocket(int port, InetAddress laddr) throws SocketException {
        return new DatagramSocket(port, laddr);
    }

    /**
     * Creates an SSL server with the specified port, listen backlog,
     * and local IP address to bind to.
     *
     * @param port the port to listen to
     * @param backlog backlog
     * @param bindAddress the address to listen to
     * @return the server socket.
     * @throws IOException problem creating socket.
     */
    public SSLServerSocket createSSLServerSocket(int port, int backlog, InetAddress bindAddress) throws IOException {
        return (SSLServerSocket) getSSLServerSocketFactory(bindAddress.getHostName(), port).createServerSocket(port, backlog, bindAddress);
    }

    /**
     * Creates a stream SSL socket and connects it to the specified
     * port number at the specified IP address.
     * @param address the address we are connecting to.
     * @param port the port we use.
     * @return the socket.
     * @throws IOException problem creating socket.
     */
    public SSLSocket createSSLSocket(InetAddress address, int port)
        throws IOException
    {
        return (SSLSocket) getSSLSocketFactory(
            address.getCanonicalHostName(), port).createSocket(address, port);
    }

    /**
     * Creates a stream SSL socket and connects it to the specified
     * port number at the specified IP address.
     * @param address the address we are connecting to.
     * @param port the port we use.
     * @param myAddress the local address to use
     * @return the socket.
     * @throws IOException problem creating socket.
     */
    public SSLSocket createSSLSocket(InetAddress address, int port,
            InetAddress myAddress)
        throws IOException
    {
        return (SSLSocket) getSSLSocketFactory(
            address.getCanonicalHostName(), port).createSocket(address, port,
                myAddress, 0);
    }

    /**
     * Creates a stream socket and connects it to the specified port number at
     * the specified IP address.
     * Comparable to "new java.net.Socket(address, port,localaddress);"
     * @param address the address to connect to.
     * @param port the port we use.
     * @param myAddress the local address to use.
     * @return the created socket.
     * @throws IOException problem creating socket.
     */
    public Socket createSocket(InetAddress address, int port,
            InetAddress myAddress)
        throws IOException
    {
        if (myAddress != null)
            return new Socket(address, port, myAddress, 0);
        else
            return new Socket(address, port);
    }

    /**
     * Creates a new Socket, binds it to myAddress:myPort and connects it to
     * address:port.
     *
     * @param address the InetAddress that we'd like to connect to.
     * @param port the port that we'd like to connect to
     * @param myAddress the address that we are supposed to bind on or null
     *        for the "any" address.
     * @param myPort the port that we are supposed to bind on or 0 for a random
     * one.
     *
     * @return a new Socket, bound on myAddress:myPort and connected to
     * address:port.
     * @throws IOException if binding or connecting the socket fail for a reason
     * (exception relayed from the corresponding Socket methods)
     */
    public Socket createSocket(InetAddress address, int port, InetAddress myAddress, int myPort) throws IOException {
        if (myAddress != null)
            return new Socket(address, port, myAddress, myPort);
        else if (port != 0) {
            //myAddress is null (i.e. any)  but we have a port number
            Socket sock = new Socket();
            sock.bind(new InetSocketAddress(port));
            sock.connect(new InetSocketAddress(address, port));
            return sock;
        } else
            return new Socket(address, port);
    }


    /**
     * Creates a ssl server socket factory.
     * @param address the address.
     * @param port the port
     * @return the server socket factory.
     * @throws IOException problem creating factory.
     */
    private SSLServerSocketFactory getSSLServerSocketFactory(String address, int port) throws IOException {
        return getSSLContext(/*SipActivator.getResources().
                getI18NString(
                    "service.gui.CERT_DIALOG_CLIENT_DESCRIPTION_TXT",
                    new String[]
                    {
                        SipActivator.getResources()
                            .getSettingsString("service.gui.APPLICATION_NAME")
                    })
                */
        address, port).getServerSocketFactory();
    }

    /**
     * Creates ssl socket factory.
     * @param address the address we are connecting to.
     * @param port the port we use.
     * @return the socket factory.
     * @throws IOException problem creating ssl socket factory.
     */
    private SSLSocketFactory getSSLSocketFactory(String address, int port) throws IOException {
        return getSSLContext(address, port).getSocketFactory();
    }


    // Create a trust manager that does not validate certificate chains
    private static final TrustManager[] trustAllCerts = {new X509TrustManager() {
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return null;
        }
        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
    }};

    /**
     * Creates the ssl context used to create ssl socket factories. Used
     * to install our custom trust manager which knows the address
     * we are connecting to.
     * @param address the address we are connecting to.
     * @param port the port
     * @return the ssl context.
     * @throws IOException problem creating ssl context.
     */
    @SuppressWarnings({"UnusedDeclaration"})
    private SSLContext getSSLContext(String address, int port) throws IOException
    {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            String algorithm = KeyManagerFactory.getDefaultAlgorithm();
            KeyManagerFactory kmFactory = KeyManagerFactory.getInstance(algorithm);
            SecureRandom secureRandom   = new SecureRandom();
            secureRandom.nextInt();
            kmFactory.init(null, null);
/*
            TrustManagerFactory tmFactory = TrustManagerFactory.getInstance(algorithm);
            tmFactory.init((KeyStore)null);
            TrustManager[] trustManagers = tmFactory.getTrustManagers();
*/
            
            sslContext.init(kmFactory.getKeyManagers(), trustAllCerts, secureRandom);

            return sslContext;
        } catch (Throwable e) {
            throw new IOException("Cannot init SSLContext: " +
                    e.getMessage());
        }
    }
}
