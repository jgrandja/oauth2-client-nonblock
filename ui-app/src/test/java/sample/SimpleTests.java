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
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ReactiveHttpInputMessage;
import org.springframework.web.reactive.function.BodyExtractor;
import org.springframework.web.reactive.function.BodyExtractors;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.blockhound.BlockHound;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * @author Joe Grandja
 */
public class SimpleTests {
	private MockWebServer server = new MockWebServer();

	@BeforeClass
	public static void setupBlockHound() {
		// IMPORTANT:
		// Before enabling BlockHound, we need to force the initialization of
		// java.lang.Package.defineSystemPackage(). When the JVM loads java.lang.Package.getSystemPackage(),
		// it attempts to java.lang.Package.loadManifest() which is blocking I/O and triggers BlockHound to error.
		// NOTE: This is an issue with JDK 8. It's been tested on JDK 10 and works fine w/o this workaround.

		// The following code forces the loading of the manifest.
		// ***** Uncomment below to fix *****
//		Class.class.getPackage();

		BlockHound.install();
	}

	@Before
	public void setupServer() {
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
	}

	@Test
	public void go() {
		WebClient client = WebClient.builder().build();

		client.get()
				.uri(this.server.url("/").uri())
				.exchange()
				.flatMap(r -> {
					ParameterizedTypeReference<Map<String, Object>> type =
							new ParameterizedTypeReference<Map<String, Object>>() {};
					BodyExtractor<Mono<Map<String, Object>>, ReactiveHttpInputMessage> delegate =
							BodyExtractors.toMono(type);
					return r.body(delegate);
				})
				.block();
	}

	private static MockResponse jsonResponse(String json) {
		return new MockResponse()
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.setBody(json);
	}
}