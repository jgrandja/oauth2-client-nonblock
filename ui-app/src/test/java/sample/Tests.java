/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.blockhound.BlockHound;
import sample.config.WebClientConfig;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.clientRegistrationId;

/**
 * @author Joe Grandja
 */
@RunWith(SpringRunner.class)
@ContextConfiguration(classes = {Tests.TestConfig.class, WebClientConfig.class })
public class Tests {

	@Autowired
	ClientRegistrationRepository clientRegistrationRepository;

	@Autowired
	OAuth2AuthorizedClientRepository authorizedClientRepository;

	@Autowired
	WebClient webClient;

	private MockWebServer server;
	private String serverUrl;
	private Authentication authentication;
	private MockHttpServletRequest request;
	private MockHttpServletResponse response;

	@BeforeClass
	public static void setUpBlockingChecks() {
		// IMPORTANT:
		// Before enabling BlockHound, we need to force the initialization of Jackson's internal cache
		// as it attempts to load the manifest from 'jackson-databind-x.x.x.jar',
		// which is a blocking I/O and therefore triggers BlockHound to error.
		// The following code forces the initialization of the cache, which ultimately calls
		// 'com.fasterxml.jackson.databind.DeserializationContext.hasValueDeserializerFor()'.
		new MappingJackson2HttpMessageConverter().canRead(
				new ParameterizedTypeReference<Map<String, Object>>() { }.getType(), null, null);

		BlockHound.install();
	}

	@Before
	public void setUp() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
		this.serverUrl = this.server.url("/").toString();
		this.authentication = new TestingAuthenticationToken("principal", "password");
		SecurityContextHolder.getContext().setAuthentication(this.authentication);
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(this.request, this.response));
	}

	@Test
	public void requestWhenAuthorizedButExpiredThenRefreshAndSendRequest() {
		String accessTokenResponse = "{\n" +
				"	\"access_token\": \"refreshed-access-token\",\n" +
				"   \"token_type\": \"bearer\",\n" +
				"   \"expires_in\": \"3600\"\n" +
				"}\n";
		String clientResponse = "{\n" +
				"	\"attribute1\": \"value1\",\n" +
				"	\"attribute2\": \"value2\"\n" +
				"}\n";

		this.server.enqueue(jsonResponse(accessTokenResponse));
		this.server.enqueue(jsonResponse(clientResponse));

		ClientRegistration clientRegistration = clientRegistration("client-a").tokenUri(this.serverUrl).build();
		when(this.clientRegistrationRepository.findByRegistrationId(eq(clientRegistration.getRegistrationId()))).thenReturn(clientRegistration);

		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant expiresAt = issuedAt.plus(Duration.ofHours(1));
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"expired-access-token", issuedAt, expiresAt, new HashSet<>(Arrays.asList("read", "write")));
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", Instant.now());
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				clientRegistration, this.authentication.getName(), accessToken, refreshToken);
		doReturn(authorizedClient).when(this.authorizedClientRepository).loadAuthorizedClient(
				eq(clientRegistration.getRegistrationId()), eq(this.authentication), eq(this.request));

		this.webClient
				.get()
				.uri(this.serverUrl)
				.attributes(clientRegistrationId(clientRegistration.getRegistrationId()))
				.retrieve()
				.bodyToMono(String.class)
				.block();

		assertThat(this.server.getRequestCount()).isEqualTo(2);

		ArgumentCaptor<OAuth2AuthorizedClient> authorizedClientCaptor = ArgumentCaptor.forClass(OAuth2AuthorizedClient.class);
		verify(this.authorizedClientRepository).saveAuthorizedClient(
				authorizedClientCaptor.capture(), eq(this.authentication), eq(this.request), eq(this.response));
		OAuth2AuthorizedClient refreshedAuthorizedClient = authorizedClientCaptor.getValue();
		assertThat(refreshedAuthorizedClient.getClientRegistration()).isSameAs(clientRegistration);
		assertThat(refreshedAuthorizedClient.getAccessToken().getTokenValue()).isEqualTo("refreshed-access-token");
	}

	private static ClientRegistration.Builder clientRegistration(String registrationId) {
		return ClientRegistration.withRegistrationId(registrationId)
				.redirectUriTemplate("{baseUrl}/{action}/oauth2/code/{registrationId}")
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.scope("read:user")
				.authorizationUri("https://example.com/login/oauth/authorize")
				.tokenUri("https://example.com/login/oauth/access_token")
				.jwkSetUri("https://example.com/oauth2/jwk")
				.userInfoUri("https://api.example.com/user")
				.userNameAttributeName("id")
				.clientName("Client Name")
				.clientId("client-id")
				.clientSecret("client-secret");
	}

	private static MockResponse jsonResponse(String json) {
		return new MockResponse()
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.setBody(json);
	}

	@Configuration
	static class TestConfig {

		@Bean
		ClientRegistrationRepository clientRegistrationRepository() {
			return mock(ClientRegistrationRepository.class);
		}

		@Bean
		OAuth2AuthorizedClientRepository authorizedClientRepository(ClientRegistrationRepository clientRegistrationRepository) {
			final OAuth2AuthorizedClientRepository delegate = new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(
					new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository));
			return spy(new OAuth2AuthorizedClientRepository() {
				@Override
				public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, Authentication principal, HttpServletRequest request) {
					return delegate.loadAuthorizedClient(clientRegistrationId, principal, request);
				}

				@Override
				public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal, HttpServletRequest request, HttpServletResponse response) {
					delegate.saveAuthorizedClient(authorizedClient, principal, request, response);
				}

				@Override
				public void removeAuthorizedClient(String clientRegistrationId, Authentication principal, HttpServletRequest request, HttpServletResponse response) {
					delegate.removeAuthorizedClient(clientRegistrationId, principal, request, response);
				}
			});
		}
	}
}