/*
 * Copyright 2026 Ada Morgan, John Regan and the IAM contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.reganjohn.iam.test.managers;

import com.github.adamorgan.jnt.api.exceptions.InvalidTokenException;
import com.github.adamorgan.jnt.api.exceptions.MissingAttributeException;
import com.github.adamorgan.jnt.api.exceptions.ProofAccessException;
import com.github.adamorgan.jnt.api.interactions.middle.digest.ContentAssertionRequest;
import com.github.adamorgan.jnt.api.managers.AccessEntryManager;
import com.github.adamorgan.jnt.api.requests.Method;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Route;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.internal.entities.AbstractEntityBuilder;
import com.github.adamorgan.jnt.internal.managers.AccessEntryManagerImpl;
import com.github.reganjohn.iam.api.exceptions.InteractionResponse;
import com.github.reganjohn.iam.api.exceptions.InteractionResponseException;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.internal.managers.AccessSignatureManagerImpl;
import com.github.reganjohn.iam.test.IntegrationTest;
import org.apache.commons.collections4.map.CaseInsensitiveMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.annotation.Nonnull;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

public class AccessSignatureManagerTest extends IntegrationTest
{
    private static final String AUTHORITY = "iam.example";
    private static final UUID OWNER_ID = UUID.fromString("02b1a26a-f033-7e2f-8ba7-543bd0ac755a");
    private static final UUID APPLICATION_ID = UUID.fromString("04d3c48c-1255-7041-8dc9-765df2ce977c");
    private static final UUID INTERACTION_ID = UUID.fromString("05e4d59d-2366-7152-9eda-876e03dfa88d");

    private AccessSignatureManagerImpl manager;

    private KeyPair pair;

    @BeforeEach
    void withAccessRaw() throws Exception
    {
        manager = new AccessSignatureManagerImpl();
        when(api.getAccessSignatureManager()).thenReturn(manager);
        if (Security.getProvider("BC") == null)
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        pair = newPair();
        channel.attr(AccessSignatureManagerImpl.CLIENT_ACCESS).set(entryOf(pair));
        AccessEntryManager entries = mock(AccessEntryManager.class);
        when(entries.getAudiences()).thenReturn(Collections.singletonList("https://" + AUTHORITY));
        channel.attr(AccessEntryManagerImpl.IDENTIFIER).set(entries);
    }

    private static KeyPair newPair() throws Exception
    {
        return KeyPairGenerator.getInstance("Ed25519", "BC").generateKeyPair();
    }

    private static AccessEntryData entryOf(KeyPair pair) throws Exception
    {
        DataObject data = AbstractEntityBuilder.createAccessSecretData(SignType.ED25519.getType(), pair, true)
                .put("kty", SignType.ED25519.getTypeRaw());
        DataObject raw = DataObject.empty()
                .put("alg", SignType.ED25519.getName())
                .put("jwk", data)
                .toData();
        return AbstractEntityBuilder.createAccessEntry(raw);
    }

    private static Route.CompiledRoute createRoute()
    {
        return Routes.Interactions.CREATE_APPLICATION_INTERACTION.compile(OWNER_ID.toString(), APPLICATION_ID.toString());
    }

    private static Route.CompiledRoute continueRoute()
    {
        return Routes.Interactions.EXECUTE_APPLICATION_INTERACTION.compile(APPLICATION_ID.toString(), INTERACTION_ID.toString());
    }

    private Request signed(Route.CompiledRoute route, KeyPair signer, long created) throws Exception
    {
        ContentAssertionRequest content = new ContentAssertionRequest.Builder(signer.getPrivate())
                .setMethod(Method.POST)
                .setAuthority(AUTHORITY)
                .setCompiledRoute("/" + route.getCompiledRoute())
                .setCreationTimestamp(created)
                .setExpirationTimestamp(0)
                .setUniqueId("client")
                .setMode(SignType.ED25519.getName())
                .setTag("jnt")
                .build();
        CaseInsensitiveMap<String, Collection<String>> headers = headers();
        headers.put("Signature-Input", Collections.singletonList(content.toString()));
        headers.put("Signature", Collections.singletonList(content.sign()));
        return new Request(context, route, headers);
    }

    private Request signed(Route.CompiledRoute route, KeyPair signer, String authorization) throws Exception
    {
        String params = "(\"@method\" \"@path\" \"authorization\");created=" + System.currentTimeMillis() / 1000;
        String base = "\"@method\": POST\n\"@path\": /" + route.getCompiledRoute() + "\n\"authorization\": " + authorization + "\n\"@signature-params\": " + params;
        Signature signature = Signature.getInstance("Ed25519", "BC");
        signature.initSign(signer.getPrivate());
        signature.update(base.getBytes(StandardCharsets.US_ASCII));
        CaseInsensitiveMap<String, Collection<String>> headers = headers();
        headers.put("Authorization", Collections.singletonList(authorization));
        headers.put("Signature-Input", Collections.singletonList("sig1=" + params));
        headers.put("Signature", Collections.singletonList("sig1=:" + Base64.getEncoder().encodeToString(signature.sign()) + ":"));
        return new Request(context, route, headers);
    }

    @Nonnull
    private static CaseInsensitiveMap<String, Collection<String>> headers()
    {
        CaseInsensitiveMap<String, Collection<String>> headers = new CaseInsensitiveMap<>();
        headers.put("Host", Collections.singletonList(AUTHORITY));
        return headers;
    }

    @Nonnull
    private Request signed(Route.CompiledRoute route) throws Exception
    {
        return signed(route, pair, System.currentTimeMillis() / 1000);
    }

    @ValueSource(booleans = {true, false})
    @ParameterizedTest
    void testValidSignature(boolean creation) throws Exception
    {
        manager.verify(context, signed(creation ? createRoute() : continueRoute()));

        assertThat((Object) channel.readInbound()).isNull();
    }


    private static DataObject rawOf(KeyPair pair) throws Exception
    {
        return AbstractEntityBuilder.createAccessSecretData(SignType.ED25519.getType(), pair, true)
                .put("kty", SignType.ED25519.getTypeRaw())
                .put("alg", SignType.ED25519.getName());
    }

    private void assertRejected(Request request, DataObject raw)
    {
        channel.attr(AccessSignatureManagerImpl.CLIENT_ACCESS).set(null);
        assertThatThrownBy(() -> manager.verify(context, request, raw))
                .isInstanceOf(InteractionResponseException.class)
                .satisfies(error -> assertThat(((InteractionResponseException) error).getError()).isEqualTo(InteractionResponse.INVALID_CLIENT));
        assertThat(channel.attr(AccessSignatureManagerImpl.CLIENT_ACCESS).get()).isNull();
    }

    @ValueSource(booleans = {true, false})
    @ParameterizedTest
    void testVerifiedKey(boolean creation) throws Exception
    {
        AccessEntryData data = manager.verify(context, signed(creation ? createRoute() : continueRoute()), rawOf(pair));

        assertThat(data.getPublic()).isEqualTo(pair.getPublic());
        assertThat(channel.attr(AccessSignatureManagerImpl.CLIENT_ACCESS).get()).isNull();
    }

    @Test
    void testVerifiedSessionKey() throws Exception
    {
        AccessEntryData data = manager.verify(context, signed(Routes.Session.ADD_SESSION.compile(), pair, "DPoP access-token"), rawOf(pair));

        assertThat(data.getPublic()).isEqualTo(pair.getPublic());
    }

    @Test
    void testSessionKeyOfAnotherSigner() throws Exception
    {
        assertRejected(signed(Routes.Session.ADD_SESSION.compile(), newPair(), "DPoP access-token"), rawOf(pair));
    }

    @Test
    void testSessionKeyWithoutAuthorization() throws Exception
    {
        assertRejected(signed(Routes.Session.ADD_SESSION.compile()), rawOf(pair));
    }

    @Test
    void testSessionKeyOfAnotherAuthorization() throws Exception
    {
        Request request = signed(Routes.Session.ADD_SESSION.compile(), pair, "DPoP access-token");
        request.getHeaders().put("Authorization", Collections.singletonList("DPoP another-token"));

        assertRejected(request, rawOf(pair));
    }

    @Test
    void testSessionSignatureWithoutAuthorization() throws Exception
    {
        Request request = signed(Routes.Session.ADD_SESSION.compile());

        assertThatThrownBy(() -> manager.verify(context, request)).isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void testVerifiedKeyOfAnotherSigner() throws Exception
    {
        assertRejected(signed(createRoute(), newPair(), System.currentTimeMillis() / 1000), rawOf(pair));
    }

    @Test
    void testKeyWithoutMaterial() throws Exception
    {
        assertRejected(signed(createRoute()), DataObject.empty().put("kty", "OKP").put("alg", "Ed25519"));
    }

    @Test
    void testWeakRsaKey() throws Exception
    {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(1024);
        DataObject raw = AbstractEntityBuilder.createAccessSecretData(SignType.RS256.getType(), generator.generateKeyPair(), true)
                .put("kty", SignType.RS256.getTypeRaw())
                .put("alg", SignType.RS256.getName());

        assertRejected(signed(createRoute()), raw);
    }

    @Test
    void testEncryptionKey() throws Exception
    {
        assertRejected(signed(createRoute()), rawOf(pair).put("use", "enc"));
    }

    @Test
    void testKeyWithoutAlgorithm() throws Exception
    {
        DataObject raw = rawOf(pair);
        raw.remove("alg");

        assertRejected(signed(createRoute()), raw);
    }

    @Test
    void testKeyWithPrivateMaterial() throws Exception
    {
        assertRejected(signed(createRoute()), rawOf(pair).put("d", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    }

    @Test
    void testKeyWithUnsignedRequest() throws Exception
    {
        assertRejected(new Request(context, createRoute(), headers()), rawOf(pair));
    }

    @Test
    void testNonceChallengeIsKept() throws Exception
    {
        AccessSignatureManagerImpl spied = spy(manager);
        when(api.getAccessSignatureManager()).thenReturn(spied);
        doThrow(new ProofAccessException("iam", "use_dpop_nonce", "A DPoP nonce is required for this request.", "nonce")).when(spied).verify(any(), any());

        assertThatThrownBy(() -> spied.verify(context, signed(createRoute()), rawOf(pair)))
                .isInstanceOf(ProofAccessException.class)
                .satisfies(error -> assertThat(((ProofAccessException) error).getNonce()).isEqualTo("nonce"));
        assertThat(channel.attr(AccessSignatureManagerImpl.CLIENT_ACCESS).get()).isNull();
    }

    @Test
    void testProofErrorWithoutNonceIsRejected() throws Exception
    {
        AccessSignatureManagerImpl spied = spy(manager);
        when(api.getAccessSignatureManager()).thenReturn(spied);
        doThrow(new ProofAccessException("iam", "invalid_request", "This action requires a signed request.")).when(spied).verify(any(), any());

        assertThatThrownBy(() -> spied.verify(context, signed(createRoute()), rawOf(pair)))
                .isInstanceOf(InteractionResponseException.class);
    }

    @Test
    void testSignatureOfAnotherKey() throws Exception
    {
        Request request = signed(createRoute(), newPair(), System.currentTimeMillis() / 1000);

        assertThatThrownBy(() -> manager.verify(context, request)).isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void testSignatureOfAnotherRoute() throws Exception
    {
        Request request = new Request(context, continueRoute(), signed(createRoute()).getHeaders());

        assertThatThrownBy(() -> manager.verify(context, request)).isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void testExpiredSignature() throws Exception
    {
        Request request = signed(createRoute(), pair, System.currentTimeMillis() / 1000 - 3600);

        assertThatThrownBy(() -> manager.verify(context, request)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void testFutureSignature() throws Exception
    {
        Request request = signed(createRoute(), pair, System.currentTimeMillis() / 1000 + 3600);

        assertThatThrownBy(() -> manager.verify(context, request)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void testMissingSignature()
    {
        Request request = new Request(context, createRoute(), headers());

        assertThatThrownBy(() -> manager.verify(context, request)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void testMissingKey() throws Exception
    {
        channel.attr(AccessSignatureManagerImpl.CLIENT_ACCESS).set(null);
        Request request = signed(createRoute());

        assertThatThrownBy(() -> manager.verify(context, request)).isInstanceOf(MissingAttributeException.class);
    }

    @Test
    void testClientRoutesAreForwardedUnverified() throws Exception
    {
        for (Route.CompiledRoute route : Arrays.asList(createRoute(), continueRoute(), Routes.Session.ADD_SESSION.compile()))
        {
            Request request = new Request(context, route, headers());

            manager.channelRead0(context, request);

            assertThat((Object) channel.readInbound()).isSameAs(request);
        }
    }

    @Test
    void testOtherRoutesRequireSignature()
    {
        Request request = new Request(context, Routes.Self.GET_SELF.compile(), headers());

        assertThatThrownBy(() -> manager.channelRead0(context, request)).isInstanceOf(ProofAccessException.class);
        assertThat((Object) channel.readInbound()).isNull();
    }

    @Test
    void testOtherRoutesNeedProofOfPossession() throws Exception
    {
        Request request = signed(Routes.Self.GET_SELF.compile());

        assertThatThrownBy(() -> manager.channelRead0(context, request)).isInstanceOf(MissingAttributeException.class);
    }

    @Test
    void testRequiredRoutes()
    {
        assertThat(manager.isRequired(context, new Request(context, createRoute(), headers()))).isTrue();
        assertThat(manager.isRequired(context, new Request(context, continueRoute(), headers()))).isTrue();
        assertThat(manager.isRequired(context, new Request(context, Routes.Self.GET_SELF.compile(), headers()))).isTrue();
    }
}
