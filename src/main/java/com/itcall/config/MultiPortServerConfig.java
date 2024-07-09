/**
 * 
 */
package com.itcall.config;

import java.util.Objects;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.servlet.server.ServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.itcall.embedded.multi_server.RedirectServletConfig;
import com.itcall.embedded.multi_server.TwoWayServletConfig;

import lombok.extern.slf4j.Slf4j;

/**
 * <pre>개정이력(Modification Information)
 * ※ spring-boot 실행 시 WebServer를 예외시킬 경우 여기서 셋팅한 웹서버 포트만 기동된다.
 *     > 웹서버 예외 실행 Code: new SpringApplicationBuilder(Application.class).web(WebApplicationType.NONE).application().run(args)
 * ※ server.http.port를 http로 실행하고, server.ssl.port를 https 포트로 실행한다.
 * ※ server.ssl.port 실행 시 ssl 인증서는 JKS파일을 기준으로 java-config 처리함.
 *     > properties나 yml을 통해 아래와 같이 설정한 경우 java-config의 ssl 설정은 제거할 것.
 *     > application.yml 설정 예시.
 * server:
 *   port: ${SSL_PORT:8443} # spring-web에 기본으로 제공할 ssl(https) 포트번호
 *   ssl:
 *     enabled: true # 위 포트번호가 ssl(https)로 기동됨. false일 경우 http로 기동됨.
 *     key-store-type: # JKS 등 키 파일 종류.
 *     key-alias: # 키파일 생성시 설정한 별칭.
 *     key-store: # 키파일 경로
 *     key-store-password: # 키파일 생성시 설정한 암호
 *   security: # spring-security를 사용하는 경우. 아래 설정을 true 로...
 *     require-ssl: true
 * 
 *     수정일           수정자     수정내용
 * ------------------------------------------
 * 2024. 7. 9.    KUEE-HAENG LEE :   최초작성
 * </pre>
 * @author KUEE-HAENG LEE
 * @version 1.0.0
 * @see
 * @since 2024. 7. 9.
 */
@Slf4j
@Configuration
public class MultiPortServerConfig {

	public static final String HTTP_SCHEME_NAME = "http";
	public static final String HTTPS_SCHEME_NAME = "https";

	@Value("${server.port:0}") // base is 8080 without ssl
	private int basePort;
	@Value("${server.http.port:0}") // 9080
	private int httpPort;
	@Value("${server.ssl.port:0}") // 9443
	private int httpsPort;

	@Value("${server.redirect.pattern:}") // /*
	private String redirectPattern;

	@Value("${server.ssl.key-store:}")
	private String keystoreFile;
	@Value("${server.ssl.key-store-type:}")
	private String keystoreType = System.getProperty("javax.net.ssl.keyStoreType", "JKS");
	@Value("${server.ssl.key-store-password:}")
	private String keystorePassword;
	@Value("${server.ssl.key-alias:}")
	private String keystoreAlias;

	@Bean
	public ServletWebServerFactory servletWebServerFactory() {
		TomcatServletWebServerFactory tomcatServletWebServerFactory = null;
		
		if(Objects.nonNull(this.redirectPattern) && this.redirectPattern.isBlank() == false) {
			RedirectServletConfig redirectServletConfig = 
					new RedirectServletConfig(this.basePort,
							this.httpPort,
							this.httpsPort,
							this.keystoreFile,
							this.keystoreType,
							this.keystorePassword,
							this.keystoreAlias);
			tomcatServletWebServerFactory = redirectServletConfig.servletContainer(this.redirectPattern);
			log.debug("Creating servlet-connector with redirect to pattern[{}]", this.redirectPattern);
		} else {
			TwoWayServletConfig twoWayServletConfig = 
					new TwoWayServletConfig(this.basePort,
							this.httpPort,
							this.httpsPort,
							this.keystoreFile,
							this.keystoreType,
							this.keystorePassword,
							this.keystoreAlias);
			tomcatServletWebServerFactory = twoWayServletConfig.servletWebServerFactory();
			log.debug("Creating servlet-connector with towWay-servlet[{}]", Stream.of(this.basePort, this.httpPort, this.httpsPort).toList());
		}
		return tomcatServletWebServerFactory;
	}

}
