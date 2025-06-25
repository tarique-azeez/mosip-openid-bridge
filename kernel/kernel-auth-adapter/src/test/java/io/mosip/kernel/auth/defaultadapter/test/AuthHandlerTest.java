package io.mosip.kernel.auth.defaultadapter.test;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.junit.After;
import org.junit.Before;
import org.mockserver.client.MockServerClient;

import java.security.Key;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.context.junit4.SpringRunner;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.TextCodec;
import io.mosip.kernel.auth.defaultadapter.config.RestTemplateInterceptor;
import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterConstant;
import io.mosip.kernel.auth.defaultadapter.handler.AuthHandler;
import io.mosip.kernel.auth.defaultadapter.helper.TokenValidationHelper;
import io.mosip.kernel.auth.defaultadapter.model.AuthToken;
import io.mosip.kernel.openid.bridge.model.MosipUserDto;
import org.springframework.util.StopWatch;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

@SpringBootTest(classes = { AuthTestBootApplication.class })
@RunWith(SpringRunner.class)
public class AuthHandlerTest extends AuthHandler {

	
	
	@Autowired
	private RestTemplateInterceptor restInterceptor;
	
	@MockBean
	private TokenValidationHelper validationHelper;
	
	@Value("${mosip.kernel.auth.adapter.ssl-bypass:true}")
	private boolean sslBypass;

	private ClientAndServer mockServer;
	private MockServerClient mockServerClient;

	@Before
	public void setUp() throws Exception {
		mockServer = ClientAndServer.startClientAndServer(1100);
		mockServerClient = new MockServerClient("localhost", 1100);
	}
	
	@Test
	public void retrieveUserTest() throws Exception {

		MosipUserDto mosipUserDto = new MosipUserDto();
		mosipUserDto.setRole("PROCESSOR");
		mosipUserDto.setUserId("110005");
		SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

		Key signingKey = new SecretKeySpec(TextCodec.BASE64.decode("1VMTZoDQr2fkbnVHc8OjsNMSmp3K6agL"),
				signatureAlgorithm.getJcaName());
		Map<String, Object> headers = new HashMap<>();
		headers.put("alg", "HS256");
		headers.put("typ", "JWT");
		String token = Jwts.builder().setHeader(headers).claim(AuthAdapterConstant.EMAIL, "mockuser@mosip.com")
				.claim(AuthAdapterConstant.MOBILE, "9210283991")
				.claim(AuthAdapterConstant.PREFERRED_USERNAME, "mock-user").claim(AuthAdapterConstant.ROLES, "ADMIN")
				.claim("userId", "mockuserid").claim("user_name", "mock-user").setSubject("mock-user")
				.setIssuedAt(Date.from(Instant.now())).setExpiration(Date.from(Instant.now().plusSeconds(345600)))
				.setAudience("account").signWith(SignatureAlgorithm.HS256, signingKey).compact();
		AuthToken authToken = new AuthToken(token);
		when(validationHelper.getTokenValidatedUserResponse(Mockito.any(),Mockito.any())).thenReturn(mosipUserDto);
		UserDetails authUserDetails = retrieveUser("110005",authToken);
		assertTrue(authUserDetails.getAuthorities().stream().anyMatch(auth -> auth.getAuthority().equals("ROLE_PROCESSOR")));
	}

	@Test
	public void testRestTemplateTimeout() throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
		mockServerClient.when(HttpRequest.request()
						.withMethod("GET")
						.withPath("/api/data"))
				.respond(HttpResponse.response()
						.withStatusCode(200)
						.withBody("Hello")
						.withDelay(TimeUnit.SECONDS, 10));

		StopWatch stopWatch = new StopWatch();
		stopWatch.start();
		try {
			getRestTemplate().getForObject("http://localhost:1100/api/data", String.class);
		} catch (ResourceAccessException e) {
			System.out.println("ResourceAccessException thrown");
		}
		stopWatch.stop();
		var elapsed = stopWatch.getTotalTimeMillis();
		System.out.println("Total time : " + elapsed);
	}

	private RestTemplate getRestTemplate() throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
		HttpClientBuilder httpClientBuilder = HttpClients.custom();
		RestTemplate restTemplate = null;

		TrustStrategy acceptingTrustStrategy = (X509Certificate[] chain, String authType) -> true;
		SSLContext sslContext = org.apache.http.ssl.SSLContexts.custom()
				.loadTrustMaterial(null, acceptingTrustStrategy).build();
		SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext, new HostnameVerifier() {
			public boolean verify(String arg0, SSLSession arg1) {
				return true;
			}
		});
		httpClientBuilder
				.setDefaultRequestConfig(RequestConfig.custom().setSocketTimeout(5000).build())
				.setSSLSocketFactory(csf);

		HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
		requestFactory.setHttpClient(httpClientBuilder.build());
		restTemplate = new RestTemplate(requestFactory);
		return restTemplate;
	}

	@After
	public void tearDown() {
		// Stop the MockServer after the test
		mockServer.stop();
	}
}
