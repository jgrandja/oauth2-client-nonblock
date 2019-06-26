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
package sample.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;

/**
 * @author Joe Grandja
 */
//@Configuration
public class OAuth2ClientConfig {

	@Bean
	OAuth2AuthorizedClientRepository authorizedClientRepository(ClientRegistrationRepository clientRegistrationRepository) {
		// The following custom configuration will force a `refresh_token` grant flow for `client-a`

		ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId("client-a");
		UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
				"user1", "password", AuthorityUtils.createAuthorityList("USER"));
		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant expiresAt = issuedAt.plus(Duration.ofHours(1));
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"expired-access-token", issuedAt, expiresAt, new HashSet<>(Arrays.asList("read", "write")));
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", Instant.now());
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				clientRegistration, authentication.getName(), accessToken, refreshToken);

		InMemoryOAuth2AuthorizedClientService authorizedClientService =
				new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
		authorizedClientService.saveAuthorizedClient(authorizedClient, authentication);

		return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService);
	}
}