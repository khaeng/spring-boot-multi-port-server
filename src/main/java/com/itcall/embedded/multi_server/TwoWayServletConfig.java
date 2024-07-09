/**
 * 
 */
package com.itcall.embedded.multi_server;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;
import java.util.stream.Stream;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.Http11NioProtocol;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileUrlResource;
import org.springframework.core.io.Resource;

import com.itcall.config.MultiPortServerConfig;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * <pre>
 * 개정이력(Modification Information)
 * 
 *	 수정일		   수정자	 수정내용
 * ------------------------------------------
 * 2024. 7. 8.	KUEE-HAENG LEE :   최초작성
 * </pre>
 * 
 * @author KUEE-HAENG LEE
 * @version 1.0.0
 * @see
 * @since 2024. 7. 8.
 */
@Slf4j
@RequiredArgsConstructor
public class TwoWayServletConfig {

	private final int basePort;
	private final int httpPort;
	private final int httpsPort;
	
	private final String keystoreFile;
	private final String keystoreType;
	private final String keystorePassword;
	private final String keystoreAlias;
	
	public TomcatServletWebServerFactory servletWebServerFactory() {
		TomcatServletWebServerFactory tomcatServletWebServerFactory = new TomcatServletWebServerFactory();
		tomcatServletWebServerFactory.addAdditionalTomcatConnectors(
				Stream.of(createHttpConnector(), createSslConnector()).filter(
						c -> Objects.nonNull(c)).toArray(
								size -> new Connector[size]));
		return tomcatServletWebServerFactory;
	}

	/**
	 * <pre>
	 * http 포트 추가.
	 * </pre>
	 * @author KUEE-HAENG LEE
	 * @return
	 */
	private Connector createHttpConnector() {
		if(this.httpPort <= 0) {
			log.info("http-port[{}] is not active-port", this.httpPort);
			return null;
		} else if(this.basePort == this.httpPort) {
			log.info("base-port[{}] is Already running http-port[{}]", this.basePort, this.httpPort);
			return null;
		}
		Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
		connector.setPort(this.httpPort);
		connector.setScheme(MultiPortServerConfig.HTTP_SCHEME_NAME);
		connector.setSecure(false);
		return connector;
	}

	/**
	 * <pre>
	 * spring.main.web-application-type=none
	 * Web서버 자동 실행 중지 후 수동으로 설정하거나, 추가 포트로 설정할 수 있음.
	 * </pre>
	 * @author KUEE-HAENG LEE
	 * @return
	 */
	private Connector createSslConnector() {
		if(this.httpPort <= 0) {
			log.info("https-port[{}] is not active-port", this.httpsPort);
			return null;
		} else if(this.basePort == this.httpsPort) {
			log.info("base-port[{}] is Already running ssl-port[{}]", this.basePort, this.httpsPort);
			return null;
		}
		Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
		connector.setPort(this.httpsPort);
		connector.setScheme(MultiPortServerConfig.HTTPS_SCHEME_NAME);
		connector.setSecure(true);
		
		Http11NioProtocol protocol = (Http11NioProtocol) connector.getProtocolHandler();
		protocol.setSSLEnabled(true);

		try {
			Resource keystoreResource = null;
			try {
				keystoreResource = new ClassPathResource(this.keystoreFile);
				if(Objects.isNull(keystoreResource) || keystoreResource.isFile() == false) {
					throw new Exception("try to external file...");
				}
			} catch (Exception e) {
				keystoreResource = new FileUrlResource(this.keystoreFile);
			}
			URL keystoreUrl = keystoreResource.getURL();
			String keystoreLocation = keystoreUrl.toString();

			SSLHostConfig sslHostConfig = new SSLHostConfig();
			SSLHostConfigCertificate sslHostConfigCertificate = new SSLHostConfigCertificate(sslHostConfig
					, SSLHostConfigCertificate.Type.UNDEFINED // UNDEFINED, RSA, DSS, EC
					);
			sslHostConfigCertificate.setCertificateKeystoreFile(keystoreLocation);
			sslHostConfigCertificate.setCertificateKeystoreType(this.keystoreType);
			sslHostConfigCertificate.setCertificateKeystorePassword(this.keystorePassword);
			sslHostConfigCertificate.setCertificateKeyAlias(this.keystoreAlias);
			
//			sslHostConfigCertificate.setSslContext(sslContext());
			
			sslHostConfig.addCertificate(sslHostConfigCertificate);
			protocol.addSslHostConfig(sslHostConfig);
		}
		catch (IOException ex) {
			throw new IllegalStateException("can't access keystore: [" + "keystore"
					+ "] or truststore: [" + "keystore" + "]", ex);
		}
		return connector;
	}

	/**
	 * SSLContext를 생성한다.
	 * CA인증서(ROOT인증서) / 서버인증서 / Private인증서(RSA)를 모두 생성한다.
	 * @param sslCertPwd
	 * @param caCertFile
	 * @param serverCertFile
	 * @param privateKeyFileOrJksFile
	 * @param sslProtocol - SslProtocol.TLS.getVersion()
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException 
	 * @throws KeyStoreException 
	 * @throws IOException 
	 * @throws InvalidKeySpecException 
	 * @throws UnrecoverableKeyException 
	 * @throws KeyManagementException 
	 */
	public static SSLContext createSslContext(String sslCertPwd, String caCertFile, String serverCertFile, String privateKeyFileOrJksFile, String sslProtocol) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException, InvalidKeySpecException, UnrecoverableKeyException, KeyManagementException {
		SSLContext sslContext = SSLContext.getInstance(Objects.isNull(sslProtocol) ? DEF_SSL_PROTOCOL : sslProtocol);
		/************
		 * 인증서 생성
		 ************/
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate caCert = (X509Certificate) cf.generateCertificate(new FileInputStream(caCertFile));

		TrustManagerFactory trustMgrFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(null); // You don't need the KeyStore instance to come from a file.
		ks.setCertificateEntry("caCert", caCert);
		trustMgrFactory.init(ks);
		
		// String sslCertPwd = "eCarPlug";
		
		byte[] serverCert = 
				Base64.getDecoder().decode(
					String.join("", Files.readAllLines(Paths.get(serverCertFile)))
						.replaceAll("-----BEGIN CERTIFICATE-----", "").replaceAll("-----END CERTIFICATE-----", "")
						.replaceAll(" ", "").replaceAll("\n", "").replaceAll("\r", "").trim()
				);
//				parseDERFromPEM(Files.readAllBytes(Paths.get(serverCertFile)),
//				"-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");

		X509Certificate cert = // generateCertificateFromDER(serverCert.getBytes());
				(X509Certificate) CertificateFactory.getInstance("X.509")
				.generateCertificate(new ByteArrayInputStream(serverCert));
		
		KeyStore keystore = KeyStore.getInstance("JKS");
		
		String priKeyOrJks = new String(Files.readAllBytes(Paths.get(privateKeyFileOrJksFile)));
		if(priKeyOrJks.contains("-----BEGIN PRIVATE KEY-----") && priKeyOrJks.contains("-----END PRIVATE KEY-----")) {
			// PrivateKey File
			byte[] privateKeyArr = Base64.getDecoder().decode(
						String.join("", priKeyOrJks).replaceAll("-----BEGIN PRIVATE KEY-----", "").replaceAll("-----END PRIVATE KEY-----", "")
						.replaceAll(" ", "").replaceAll("\n", "").replaceAll("\r", "").trim() );
//					parseDERFromPEM(Files.readAllBytes(Paths.get(privateKeyFileOrJksFile)), "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----");
			RSAPrivateKey privateKey = // generatePrivateKeyFromDER(privateKeyStr.getBytes());
					(RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeyArr));
			
			keystore.load(null);
			keystore.setCertificateEntry("cert-alias", cert);
			keystore.setKeyEntry("key-alias", privateKey, sslCertPwd.toCharArray(), new Certificate[]{cert});
		} else {
			// JKS File
			keystore.load(new FileInputStream(privateKeyFileOrJksFile), sslCertPwd.toCharArray());
			keystore.setCertificateEntry("cert-alias", cert);
		}
		
		
		

		// Load key manager
		KeyManagerFactory keyMgrFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()); // "SunX509"
		keyMgrFactory.init(keystore, sslCertPwd.toCharArray());

		// Create SSL context
		
		sslContext.init(keyMgrFactory.getKeyManagers(), trustMgrFactory.getTrustManagers(), null);
		return sslContext;
	}

	/************************************************************
	 * JKS파일로 SSL_CONTEXT 생성
	 * @param sslCertPwd
	 * @param certJksFile
	 * @param sslProtocol
	 * @return
	 */
	public static SSLContext createSslContext(String sslCertPwd, String certJksFile, String serverCertFile,
			String sslProtocol) {
		try {
			byte[] serverCert = 
					Base64.getDecoder().decode(String.join("", Files.readAllLines(Paths.get(serverCertFile)))
							.replaceAll("-----BEGIN CERTIFICATE-----", "").replaceAll("-----END CERTIFICATE-----", "")
							.replaceAll(" ", "").replaceAll("\n", "").replaceAll("\r", "").trim());
//					parseDERFromPEM(Files.readAllBytes(Paths.get(serverCertFile)),
//					"-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");
			X509Certificate cert = // generateCertificateFromDER(serverCert.getBytes());
					(X509Certificate) CertificateFactory.getInstance("X.509")
							.generateCertificate(new ByteArrayInputStream(serverCert));

			InputStream is = new FileInputStream(certJksFile);
			// Load keystore
			KeyStore keystore = KeyStore.getInstance("JKS");
			keystore.load(is, sslCertPwd.toCharArray());
			keystore.setCertificateEntry("cert-alias", cert);

			// Load trust manager
			TrustManagerFactory trustMgrFactory = TrustManagerFactory
					.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			trustMgrFactory.init(keystore);

			// Load key manager
			KeyManagerFactory keyMgrFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			keyMgrFactory.init(keystore, sslCertPwd.toCharArray());

			// Create SSL context
			SSLContext sslContext = SSLContext
					.getInstance(Objects.isNull(sslProtocol) ? DEF_SSL_PROTOCOL : sslProtocol);
			sslContext.init(keyMgrFactory.getKeyManagers(), trustMgrFactory.getTrustManagers(), null);
			return sslContext;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	private static final String DEF_SSL_PROTOCOL = "TLS";
	private static final String[] SSL_PROTOCOLS = new String[] {"SSL","SSLv2","SSLv3","TLS","TLSv1","TLSv1.1","TLSv1.2","TLSv1.3"};
//	SSL("SSL") // Supports some version of SSL; may support other versions
//	, SSLv2("SSLv2") // Supports SSL version 2 or later; may support other versions
//	, SSLv3("SSLv3") // Supports SSL version 3; may support other versions
//	, TLS("TLS") // Supports some version of TLS; may support other versions
//	, TLSv1("TLSv1") // Supports RFC 2246: TLS version 1.0 ; may support other versions
//	, TLSv1_1("TLSv1.1") // Supports RFC 4346: TLS version 1.1 ; may support other versions
//	, TLSv1_2("TLSv1.2") // Supports RFC 5246: TLS version 1.2 ; may support other versions
//	, TLSv1_3("TLSv1.3") // Supports RFC 5246: TLS version 1.3 ; may support other versions
}
