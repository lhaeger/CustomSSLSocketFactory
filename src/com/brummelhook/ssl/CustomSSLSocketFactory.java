package com.brummelhook.ssl;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

public class CustomSSLSocketFactory extends SSLSocketFactory
{
	private SSLSocketFactory sslSocketFactory;

	private static volatile CustomSSLSocketFactory singletonCustLdapSslSockFact;

	// https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyStore
	private static String DEFAULT_TRUSTSTORE_TYPE = "JKS";
	
	// https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SSLContext
	private static String DEFAULT_SSLCTX_PROTOCOL = "TLSv1.2";

	private CustomSSLSocketFactory() throws KeyManagementException, KeyStoreException, FileNotFoundException, NoSuchAlgorithmException, CertificateException, IOException
	{
		String trustStore = System.getProperty("com.brummelhook.ssl.trustStore");
		String trustStoreType = System.getProperty("com.brummelhook.ssl.trustStoreType");
		String trustStorePassword = System.getProperty("com.brummelhook.ssl.trustStorePassword");
		String sslContextProtocol = System.getProperty("com.brummelhook.ssl.sslContextProtocol");

		sslSocketFactory = loadTrustStoreProgrammatically(trustStore, trustStorePassword, trustStoreType, sslContextProtocol);
	}

	private CustomSSLSocketFactory(String trustStore, String trustStorePassword, String trustStoreType, String sslContextProtocol) throws KeyManagementException, KeyStoreException, FileNotFoundException, NoSuchAlgorithmException, CertificateException, IOException
	{
		sslSocketFactory = loadTrustStoreProgrammatically(trustStore, trustStorePassword, trustStoreType, sslContextProtocol);
	}

	private static CustomSSLSocketFactory getSingletonInstance() throws KeyManagementException, KeyStoreException, FileNotFoundException, NoSuchAlgorithmException, CertificateException, IOException
	{
		if (CustomSSLSocketFactory.singletonCustLdapSslSockFact == null)
		{
			synchronized (CustomSSLSocketFactory.class)
			{
				if (CustomSSLSocketFactory.singletonCustLdapSslSockFact == null)
				{
					CustomSSLSocketFactory.singletonCustLdapSslSockFact = new CustomSSLSocketFactory();
				}
			}
		}

		return CustomSSLSocketFactory.singletonCustLdapSslSockFact;
	}

	public static SocketFactory getDefault()
	{
		/*
		 * This method is called by LDAP implementations to create the custom
		 * SSL socket factory.
		 * 
		 * There are times when you need to have more control over the SSL
		 * sockets, or sockets in general, used by the LDAP service provider. To
		 * set the socket factory implementation used by the LDAP service
		 * provider, set the "java.naming.ldap.factory.socket" property to the
		 * fully qualified class name of the socket factory. That class must
		 * extend the javax.net.SocketFactory abstract class and provide an
		 * implementation of the getDefault() method that returns an instance of
		 * the custom socket factory. See:
		 * https://docs.oracle.com/javase/jndi/tutorial/ldap/security/ssl.html
		 */
		CustomSSLSocketFactory customSSLSocketFactory = null;

		try
		{
			customSSLSocketFactory = CustomSSLSocketFactory.getSingletonInstance();
		} catch (Exception e)
		{
			StringWriter sw = new StringWriter();
			e.printStackTrace(new PrintWriter(sw));
			throw new RuntimeException("Failed to create CustomSSLSocketFactory. Exception: " + e.getClass().getSimpleName() + ". \nReason: " + sw.toString(), e);
		}

		return customSSLSocketFactory;
	}

	public static SocketFactory getInstance(String trustStore, String trustStorePassword, String trustStoreType, String sslContextProtocol)
	{
		CustomSSLSocketFactory customSSLSocketFactory = null;
		
		try
		{
			customSSLSocketFactory = new CustomSSLSocketFactory(trustStore, trustStorePassword, trustStoreType, sslContextProtocol);
		} catch (Exception e)
		{
			StringWriter sw = new StringWriter();
			e.printStackTrace(new PrintWriter(sw));
			throw new RuntimeException("Failed to create CustomSSLSocketFactory. Exception: " + e.getClass().getSimpleName() + ". \nReason: " + sw.toString(), e);
		}

		return customSSLSocketFactory;
	}

	public static SocketFactory getInstance(String trustStore, String trustStorePassword, String trustStoreType)
	{
		return getInstance(trustStore, trustStorePassword, trustStoreType, null);
	}

	public static SocketFactory getInstance(String trustStore, String trustStorePassword)
	{
		return getInstance(trustStore, trustStorePassword, null, null);
	}

	private SSLSocketFactory loadTrustStoreProgrammatically(String trustStore, String trustStorePassword, String trustStoreType, String sslContextProtocol) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, KeyManagementException, CertificateException
	{

		if (null == trustStoreType)
			trustStoreType = DEFAULT_TRUSTSTORE_TYPE;
		
		KeyStore keyStore = KeyStore.getInstance(trustStoreType);

		try (BufferedInputStream bisTrustStore = new BufferedInputStream(new FileInputStream(trustStore)))
		{
			keyStore.load(bisTrustStore, trustStorePassword != null ? trustStorePassword.toCharArray() : null);
		}

		// initialize a trust manager factory with the trusted store
		TrustManagerFactory trustFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		trustFactory.init(keyStore);

		// get the trust managers from the factory
		TrustManager[] trustManagers = trustFactory.getTrustManagers();

		// initialize an SSL context to use these managers
		if (null == sslContextProtocol)
			sslContextProtocol = DEFAULT_SSLCTX_PROTOCOL;

		SSLContext sslContext = SSLContext.getInstance(sslContextProtocol);
		sslContext.init(null, trustManagers, null);

		SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

		return sslSocketFactory;
	}

	@Override
	public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException
	{
		return sslSocketFactory.createSocket(s, host, port, autoClose);
	}

	@Override
	public String[] getDefaultCipherSuites()
	{
		return sslSocketFactory.getDefaultCipherSuites();
	}

	@Override
	public String[] getSupportedCipherSuites()
	{
		return sslSocketFactory.getSupportedCipherSuites();
	}

	@Override
	public Socket createSocket(String host, int port) throws IOException, UnknownHostException
	{
		return sslSocketFactory.createSocket(host, port);
	}

	@Override
	public Socket createSocket(InetAddress host, int port) throws IOException
	{
		return sslSocketFactory.createSocket(host, port);
	}

	@Override
	public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException, UnknownHostException
	{
		return sslSocketFactory.createSocket(localHost, port, localHost, localPort);
	}

	@Override
	public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException
	{
		return sslSocketFactory.createSocket(address, port, localAddress, localPort);
	}
}