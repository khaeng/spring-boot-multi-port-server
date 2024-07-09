/**
 * 
 */
package com.itcall.embedded.multi_server;

import java.io.IOException;
import java.net.URL;
import java.util.Objects;
import java.util.stream.Stream;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.Http11NioProtocol;
import org.apache.tomcat.util.descriptor.web.SecurityCollection;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileUrlResource;
import org.springframework.core.io.Resource;

import com.itcall.config.MultiPortServerConfig;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * <pre>개정이력(Modification Information)
 * 
 *     수정일           수정자     수정내용
 * ------------------------------------------
 * 2024. 7. 8.    KUEE-HAENG LEE :   최초작성
 * </pre>
 * @author KUEE-HAENG LEE
 * @version 1.0.0
 * @see
 * @since 2024. 7. 8.
 */
@Slf4j
@RequiredArgsConstructor
// @ConditionalOnProperty(prefix = "server.redirect", name = "pattern")
public class RedirectServletConfig {

	private final int basePort;
	private final int httpPort;
	private final int httpsPort;
	
	private final String keystoreFile;
	private final String keystoreType;
	private final String keystorePassword;
	private final String keystoreAlias;

	public TomcatServletWebServerFactory servletContainer(
			@Value("${server.redirect.pattern:/*}") final String redirectPattern
			) {
		TomcatServletWebServerFactory tomcat = new TomcatServletWebServerFactory() {
			@Override
			protected void postProcessContext(Context context) {
				SecurityConstraint securityConstraint = new SecurityConstraint();
				securityConstraint.setUserConstraint("CONFIDENTIAL");
				SecurityCollection collection = new SecurityCollection();
				collection.addPattern(redirectPattern);
				securityConstraint.addCollection(collection);
				context.addConstraint(securityConstraint);
			}
		};

		tomcat.addAdditionalTomcatConnectors(
				Stream.of(redirectConnector(), createSslConnector()).filter(
						c -> Objects.nonNull(c)).toArray(
								size -> new Connector[size]));
		return tomcat;
	}

	private Connector redirectConnector() {
		if(this.httpPort <= 0) {
			log.info("http-port[{}] is not active-port", this.httpPort);
			return null;
		} else if(this.basePort == this.httpPort) {
			log.info("base-port[{}] is Already running http-port[{}]", this.basePort, this.httpPort);
			return null;
		}
		Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
		connector.setScheme(MultiPortServerConfig.HTTP_SCHEME_NAME);
		connector.setPort(this.httpPort);
		connector.setSecure(false);
		if(this.basePort > 0) {
			connector.setRedirectPort(this.basePort);
		} else {
			connector.setRedirectPort(this.httpsPort);
		}
		return connector;
	}

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
			SSLHostConfigCertificate sslHostConfigCertificate = new SSLHostConfigCertificate(sslHostConfig,
					SSLHostConfigCertificate.Type.UNDEFINED // UNDEFINED, RSA, DSS, EC
			);
			sslHostConfigCertificate.setCertificateKeystoreFile(keystoreLocation);
			sslHostConfigCertificate.setCertificateKeystoreType(this.keystoreType);
			sslHostConfigCertificate.setCertificateKeystorePassword(this.keystorePassword);
			sslHostConfigCertificate.setCertificateKeyAlias(this.keystoreAlias);

//			sslHostConfigCertificate.setSslContext(sslContext());

			sslHostConfig.addCertificate(sslHostConfigCertificate);
			protocol.addSslHostConfig(sslHostConfig);
		} catch (IOException ex) {
			throw new IllegalStateException(
					"can't access keystore: [" + "keystore" + "] or truststore: [" + "keystore" + "]", ex);
		}
		return connector;
	}

}
