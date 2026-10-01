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

package com.github.reganjohn.iam.test.restaction.interactions;

import com.github.adamorgan.jnt.api.exceptions.ProofAccessException;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.socket.SocketManager;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextData;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextType;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.api.utils.jose.ProofObjectData;
import com.github.adamorgan.jnt.api.utils.requestbody.RequestBody;
import com.github.adamorgan.jnt.internal.JNTImpl;
import com.github.adamorgan.jnt.internal.managers.ProofObjectManagerImpl;
import com.github.reganjohn.iam.api.Permission;
import com.github.reganjohn.iam.api.entities.Application;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.events.applications.interactions.InteractionCreateEvent;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.exceptions.InteractionResponse;
import com.github.reganjohn.iam.api.exceptions.InteractionResponseException;
import com.github.reganjohn.iam.api.interactions.ApplicationContextInteraction;
import com.github.reganjohn.iam.internal.requests.restactions.interactions.ApplicationInteractionCreateActionImpl;
import com.github.reganjohn.iam.test.assertions.restaction.RestActionAssertions;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import com.reganjohn.c4j.internal.requests.objaction.InteractionMappingActionImpl;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class ApplicationInteractionCreateActionTest extends RestActionTest
{
    private static final UUID OWNER_ID = UUID.fromString("02b1a26a-f033-7e2f-8ba7-543bd0ac755a");
    private static final UUID APPLICATION_ID = UUID.fromString("04d3c48c-1255-7041-8dc9-765df2ce977c");
    private static final String CALLBACK = "https://example.org/callback";
    private static final String BASE_URI = "https://iam.example/";
    private static final String CLIENT_NONCE = "client-nonce-0123";

    private AccessEntryData proofEntry;

    @BeforeEach
    void withBaseUri()
    {
        when(api.getBaseUri()).thenReturn(BASE_URI);
    }

    private ApplicationInteractionCreateActionImpl newAction()
    {
        return new ApplicationInteractionCreateActionImpl(api);
    }

    private ApplicationInteractionCreateActionImpl newAction(ArgumentCaptor<ApplicationContextInteraction> created, boolean verified)
    {
        ApplicationInteractionCreateActionImpl action = spy(newAction());
        doAnswer(invocation ->
        {
            if (verified)
                ((Runnable) invocation.getArgument(3)).run();
            return null;
        }).when(action).checkClient(any(), any(), any(), any());
        doReturn(completed(null)).when(action).createInteraction(created.capture());
        return action;
    }

    private void withProofOfClient()
    {
        proofEntry = withProof(SignType.ED25519);
    }

    private void withStoredApplication()
    {
        Application application = withApplication(APPLICATION_ID, OWNER_ID, "app", null, null, "https://example.org", 0, CALLBACK);
        User owner = withUser(OWNER_ID, "bob", null, 0);
        withApplication(owner, APPLICATION_ID, completed(application));
        withRetrieval(OWNER_ID, completed(owner));
    }

    private static DataObject grant()
    {
        DataObject read = DataObject.empty().put("type", "account").put("actions", DataArray.empty().add("read"));
        return DataObject.empty()
                .put("access_token", DataObject.empty().put("access", DataArray.empty().add(read)))
                .put("client", DataObject.empty().put("display", DataObject.empty().put("name", "app")))
                .put("interact", DataObject.empty()
                        .put("start", DataArray.empty().add("redirect"))
                        .put("finish", DataObject.empty()
                                .put("method", "redirect")
                                .put("uri", CALLBACK)
                                .put("nonce", CLIENT_NONCE)));
    }

    private static String grant(Consumer<DataObject> change)
    {
        DataObject grant = grant();
        change.accept(grant);
        return grant.toString();
    }

    private static Consumer<DataObject> finish(Consumer<DataObject> change)
    {
        return grant -> change.accept(grant.getObject("interact").getObject("finish"));
    }

    private static Consumer<DataObject> token(Consumer<DataObject> change)
    {
        return grant -> change.accept(grant.getObject("access_token"));
    }

    private static Consumer<DataObject> clientKey(String proof, DataObject jwk)
    {
        return grant -> grant.getObject("client").put("key", DataObject.empty().put("proof", proof).put("jwk", jwk));
    }

    private static Consumer<DataObject> interact(Consumer<DataObject> change)
    {
        return grant -> change.accept(grant.getObject("interact"));
    }

    private RestActionAssertions assertThatGranting(ApplicationInteractionCreateActionImpl action, String json)
    {
        return assertThatRequestTo(action)
                .withRouteParams(OWNER_ID.toString(), APPLICATION_ID.toString())
                .withJsonBody(json);
    }

    static Stream<Arguments> testInvalidRequests()
    {
        DataObject push = DataObject.empty().put("method", "push");
        return Stream.of(
                arguments("missing_access_token", grant(grant -> grant.remove("access_token"))),
                arguments("access_token_not_object", grant(grant -> grant.put("access_token", "token"))),
                arguments("access_missing", grant(token(token -> token.remove("access")))),
                arguments("access_not_array", grant(token(token -> token.put("access", "account")))),
                arguments("access_empty", grant(token(token -> token.put("access", DataArray.empty())))),
                arguments("access_entry_string", grant(token(token -> token.put("access", DataArray.empty().add("account"))))),
                arguments("access_entry_without_actions", grant(token(token -> token.put("access", DataArray.empty().add(DataObject.empty().put("type", "account")))))),
                arguments("access_entry_without_type", grant(token(token -> token.put("access", DataArray.empty().add(DataObject.empty().put("actions", DataArray.empty().add("read"))))))),
                arguments("access_unknown_type", grant(token(token -> token.put("access", DataArray.empty().add(DataObject.empty().put("type", "photo").put("actions", DataArray.empty().add("read"))))))),
                arguments("access_unknown_action", grant(token(token -> token.put("access", DataArray.empty().add(DataObject.empty().put("type", "account").put("actions", DataArray.empty().add("write"))))))),
                arguments("access_action_not_string", grant(token(token -> token.put("access", DataArray.empty().add(DataObject.empty().put("type", "account").put("actions", DataArray.empty().add(5))))))),
                arguments("label_not_string", grant(token(token -> token.put("label", 5)))),
                arguments("missing_client", grant(grant -> grant.remove("client"))),
                arguments("client_string", grant(grant -> grant.put("client", "instance"))),
                arguments("missing_interact", grant(grant -> grant.remove("interact"))),
                arguments("interact_not_object", grant(grant -> grant.put("interact", "redirect"))),
                arguments("start_missing", grant(interact(interact -> interact.remove("start")))),
                arguments("start_not_array", grant(interact(interact -> interact.put("start", "redirect")))),
                arguments("start_without_redirect", grant(interact(interact -> interact.put("start", DataArray.empty().add("app"))))),
                arguments("start_empty", grant(interact(interact -> interact.put("start", DataArray.empty())))),
                arguments("finish_missing", grant(interact(interact -> interact.remove("finish")))),
                arguments("finish_not_object", grant(interact(interact -> interact.put("finish", "redirect")))),
                arguments("finish_push", grant(interact(interact -> interact.put("finish", push)))),
                arguments("finish_method_missing", grant(finish(finish -> finish.remove("method")))),
                arguments("finish_method_unknown", grant(finish(finish -> finish.put("method", "poll")))),
                arguments("finish_uri_missing", grant(finish(finish -> finish.remove("uri")))),
                arguments("finish_uri_not_string", grant(finish(finish -> finish.put("uri", 5)))),
                arguments("finish_uri_not_url", grant(finish(finish -> finish.put("uri", "not-a-url")))),
                arguments("finish_nonce_missing", grant(finish(finish -> finish.remove("nonce")))),
                arguments("finish_nonce_empty", grant(finish(finish -> finish.put("nonce", "")))),
                arguments("finish_nonce_too_short", grant(finish(finish -> finish.put("nonce", "1")))),
                arguments("finish_nonce_one_below_minimum", grant(finish(finish -> finish.put("nonce", "a".repeat(15))))),
                arguments("finish_nonce_one_above_maximum", grant(finish(finish -> finish.put("nonce", "a".repeat(257))))),
                arguments("finish_nonce_not_string", grant(finish(finish -> finish.put("nonce", 5)))),
                arguments("finish_hash_method_not_string", grant(finish(finish -> finish.put("hash_method", 5)))),
                arguments("finish_hash_method_unknown", grant(finish(finish -> finish.put("hash_method", "md5")))));
    }

    static Stream<Arguments> testInvalidPath()
    {
        return Stream.of(
                arguments("owner_empty", "", APPLICATION_ID.toString()),
                arguments("owner_not_uuid", "not-a-uuid", APPLICATION_ID.toString()),
                arguments("owner_too_short", "02b1a26a-f033-7e2f-8ba7", APPLICATION_ID.toString()),
                arguments("application_empty", OWNER_ID.toString(), ""),
                arguments("application_not_uuid", OWNER_ID.toString(), "not-a-uuid"),
                arguments("application_too_short", OWNER_ID.toString(), "04d3c48c-1255-7041-8dc9"),
                arguments("both_invalid", "not-a-uuid", "not-a-uuid"));
    }

    @Test
    void testNonObject()
    {
        withProofOfClient();

        assertThatRequestTo(newAction())
                .withRouteParams(OWNER_ID.toString(), APPLICATION_ID.toString())
                .withBody(nonObjectBody())
                .hasInteractionResponse(InteractionResponse.INVALID_REQUEST, ErrorResponse.INVALID_FORM_BODY)
                .hasNoResponse()
                .whenHandled();
    }

    @Test
    void testForeignBody()
    {
        withProofOfClient();

        assertThatRequestTo(newAction())
                .withRouteParams(OWNER_ID.toString(), APPLICATION_ID.toString())
                .withBody(mock(RequestBody.class))
                .hasInteractionResponse(InteractionResponse.INVALID_REQUEST, ErrorResponse.INVALID_FORM_BODY)
                .hasNoResponse()
                .whenHandled();
    }

    @MethodSource
    @ParameterizedTest(name = "{0}")
    void testInvalidPath(String name, String ownerId, String applicationId)
    {
        withProofOfClient();

        assertThatRequestTo(newAction())
                .withRouteParams(ownerId, applicationId)
                .withJsonBody(grant().toString())
                .hasInteractionResponse(InteractionResponse.INVALID_REQUEST, ErrorResponse.INVALID_FORM_BODY)
                .hasNoResponse()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @MethodSource
    @ParameterizedTest(name = "{0}")
    void testInvalidRequests(String name, String json)
    {
        withProofOfClient();

        assertThatGranting(newAction(), json)
                .hasInteractionResponse(InteractionResponse.INVALID_REQUEST, ErrorResponse.INVALID_FORM_BODY)
                .hasNoResponse()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @ValueSource(strings = {"bearer", "durable", "split"})
    @ParameterizedTest
    void testUnsupportedFlags(String flag)
    {
        withProofOfClient();

        assertThatGranting(newAction(), grant(token(token -> token.put("flags", DataArray.empty().add(flag)))))
                .hasInteractionResponse(InteractionResponse.INVALID_FLAG, ErrorResponse.INVALID_FORM_BODY)
                .hasNoResponse()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testFlagsNotArray()
    {
        withProofOfClient();

        assertThatGranting(newAction(), grant(token(token -> token.put("flags", "bearer"))))
                .hasInteractionResponse(InteractionResponse.INVALID_FLAG, ErrorResponse.INVALID_FORM_BODY)
                .hasNoResponse()
                .whenHandled();
    }

    @Test
    void testMissingProof()
    {
        assertThatGranting(newAction(), grant().toString())
                .hasNoResponse()
                .hasFailureOfType(ProofAccessException.class)
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testProofWithoutThumbprint()
    {
        withProofOfClient();
        channel.attr(ProofObjectManagerImpl.CONTEXT).set(mock(ProofObjectData.class));

        assertThatGranting(newAction(), grant().toString())
                .hasNoResponse()
                .hasInteractionResponse(InteractionResponse.INVALID_CLIENT, ErrorResponse.INVALID_TOKEN)
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testUnknownOwner()
    {
        withProofOfClient();
        withRetrieval(OWNER_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_USER)));

        assertThatGranting(newAction(), grant().toString())
                .hasNoResponse()
                .hasInteractionResponse(InteractionResponse.INVALID_CLIENT, ErrorResponse.UNKNOWN_USER)
                .whenHandled();
    }

    @Test
    void testUnknownApplication()
    {
        withProofOfClient();
        User owner = withUser(OWNER_ID, "bob", null, 0);
        withApplication(owner, APPLICATION_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_APPLICATION)));
        withRetrieval(OWNER_ID, completed(owner));

        assertThatGranting(newAction(), grant().toString())
                .hasNoResponse()
                .hasInteractionResponse(InteractionResponse.INVALID_CLIENT, ErrorResponse.UNKNOWN_APPLICATION)
                .whenHandled();
    }

    @Test
    void testOtherFailure()
    {
        withProofOfClient();
        withRetrieval(OWNER_ID, failed(new ErrorResponseException(ErrorResponse.MISSING_ACCESS)));

        assertThatGranting(newAction(), grant().toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .whenHandled();
    }

    @ValueSource(strings = {
            "https://example.org/other",
            "https://example.org/callback/",
            "https://example.org/callback?x=1",
            "HTTPS://EXAMPLE.ORG/callback",
            "http://example.org/callback"})
    @ParameterizedTest
    void testUnregisteredFinishUri(String uri)
    {
        withProofOfClient();
        withStoredApplication();
        ArgumentCaptor<ApplicationContextInteraction> created = ArgumentCaptor.forClass(ApplicationContextInteraction.class);

        assertThatGranting(newAction(created, true), grant(finish(finish -> finish.put("uri", uri))))
                .hasNoResponse()
                .hasInteractionResponse(InteractionResponse.INVALID_REQUEST, ErrorResponse.INVALID_FORM_BODY)
                .whenHandled();

        assertThat(created.getAllValues()).isEmpty();
    }

    @Test
    void testUnverifiedClient()
    {
        withProofOfClient();
        withStoredApplication();
        ArgumentCaptor<ApplicationContextInteraction> created = ArgumentCaptor.forClass(ApplicationContextInteraction.class);

        assertThatGranting(newAction(created, false), grant().toString())
                .hasNoResponse()
                .whenHandled();

        assertThat(created.getAllValues()).isEmpty();
    }

    @Test
    void testValidGrant()
    {
        withProofOfClient();
        withStoredApplication();
        List<Object> events = withEventRecorder();
        ArgumentCaptor<ApplicationContextInteraction> created = ArgumentCaptor.forClass(ApplicationContextInteraction.class);
        OffsetDateTime before = OffsetDateTime.now();

        assertThatGranting(newAction(created, true), grant().toString())
                .hasStatus(StatusReason.OK.code)
                .hasContentType(ApplicationInteractionCreateActionImpl.MEDIA_TYPE_JSON)
                .hasJsonBody(json ->
                {
                    ApplicationContextInteraction interaction = created.getValue();
                    String id = interaction.getUniqueId().toString();
                    DataObject interact = json.getObject("interact");
                    DataObject next = json.getObject("continue");
                    assertThat(interact.getString("redirect")).isEqualTo("https://iam.example/users/" + OWNER_ID + "/applications/" + APPLICATION_ID + "/interactions/" + id);
                    assertThat(interact.getString("finish")).isEqualTo(interaction.getFinishNonce());
                    assertThat(interact.getInt("expires_in")).isEqualTo(300);
                    assertThat(next.getString("uri")).isEqualTo("https://iam.example/applications/" + APPLICATION_ID + "/interactions/" + id);
                    assertThat(digestOf(next.getObject("access_token").getString("value"))).isEqualTo(interaction.hash());
                    assertThat(json.toMap().keySet()).containsExactlyInAnyOrder("interact", "continue");
                })
                .whenHandled();

        ApplicationContextInteraction interaction = created.getValue();
        assertThat(interaction.getOwnerId()).isEqualTo(OWNER_ID);
        assertThat(interaction.getApplicationId()).isEqualTo(APPLICATION_ID);
        assertThat(interaction.getUniqueId()).isNotNull();
        assertThat(interaction.getPermissionsRaw()).isEqualTo(Permission.VIEW_ACCOUNT.getRawValue());
        assertThat(interaction.getRedirectUri()).isEqualTo(CALLBACK);
        assertThat(interaction.getClientNonce()).isEqualTo(CLIENT_NONCE);
        assertThat(interaction.getFinishNonce()).isNotEmpty().isNotEqualTo(CLIENT_NONCE);
        assertThat(interaction.getMethodHash()).isEqualTo("sha-256");
        assertThat(interaction.getUri()).isEqualTo("https://iam.example/users/" + OWNER_ID + "/applications/" + APPLICATION_ID + "/interactions");
        assertThat(interaction.getTimeExpiresAt()).isBetween(before.plusSeconds(299), OffsetDateTime.now().plusSeconds(301));
        assertThat(interaction.getThumbprint()).isEqualTo(thumbprintOf(proofEntry));
        assertThat(interaction.getLabel()).isNull();
        assertThat(interaction.getLabel()).isNull();
        assertThat(events).hasSize(1);
        assertThat(events.get(0)).isInstanceOf(InteractionCreateEvent.class);
        assertThat(((InteractionCreateEvent) events.get(0)).getInteraction()).isSameAs(interaction);
    }

    @ValueSource(ints = {16, 256})
    @ParameterizedTest
    void testNonceLengthBounds(int length)
    {
        withProofOfClient();
        withStoredApplication();
        ArgumentCaptor<ApplicationContextInteraction> created = ArgumentCaptor.forClass(ApplicationContextInteraction.class);
        String nonce = "a".repeat(length);

        assertThatGranting(newAction(created, true), grant(finish(finish -> finish.put("nonce", nonce))))
                .hasStatus(StatusReason.OK.code)
                .whenHandled();

        assertThat(created.getValue().getClientNonce()).isEqualTo(nonce);
    }

    @ValueSource(strings = {"sha-256", "sha-384", "sha-512", "sha3-256", "sha3-384", "sha3-512"})
    @ParameterizedTest
    void testHashMethod(String method)
    {
        withProofOfClient();
        withStoredApplication();
        ArgumentCaptor<ApplicationContextInteraction> created = ArgumentCaptor.forClass(ApplicationContextInteraction.class);

        assertThatGranting(newAction(created, true), grant(finish(finish -> finish.put("hash_method", method))))
                .hasStatus(StatusReason.OK.code)
                .whenHandled();

        assertThat(created.getValue().getMethodHash()).isEqualTo(method);
    }

    @Test
    void testHostHeadersIgnored()
    {
        withProofOfClient();
        withStoredApplication();
        ArgumentCaptor<ApplicationContextInteraction> created = ArgumentCaptor.forClass(ApplicationContextInteraction.class);

        assertThatRequestTo(newAction(created, true))
                .withRouteParams(OWNER_ID.toString(), APPLICATION_ID.toString())
                .withHeader("Host", "internal.local")
                .withHeader("Forwarded", "proto=http;host=edge.example")
                .withJsonBody(grant().toString())
                .hasStatus(StatusReason.OK.code)
                .hasJsonBody(json -> assertThat(json.getObject("interact").getString("redirect")).startsWith(BASE_URI + "users/"))
                .whenHandled();

        assertThat(created.getValue().getUri()).startsWith(BASE_URI + "users/");
    }

    @Test
    void testManyAccessEntries()
    {
        withProofOfClient();
        withStoredApplication();
        ArgumentCaptor<ApplicationContextInteraction> created = ArgumentCaptor.forClass(ApplicationContextInteraction.class);
        DataObject read = DataObject.empty().put("type", "account").put("actions", DataArray.empty().add("read").add("read"));

        assertThatGranting(newAction(created, true), grant(token(token -> token.put("access", DataArray.empty().add(read).add(read)))))
                .hasStatus(StatusReason.OK.code)
                .whenHandled();

        assertThat(created.getValue().getPermissionsRaw()).isEqualTo(Permission.VIEW_ACCOUNT.getRawValue());
    }

    @Test
    void testLabel()
    {
        withProofOfClient();
        withStoredApplication();
        ArgumentCaptor<ApplicationContextInteraction> created = ArgumentCaptor.forClass(ApplicationContextInteraction.class);

        assertThatGranting(newAction(created, true), grant(token(token -> token.put("label", "my-token"))))
                .hasStatus(StatusReason.OK.code)
                .whenHandled();

        assertThat(created.getValue().getLabel()).isEqualTo("my-token");
    }

    @Test
    void testClientKeyOfProof()
    {
        withProofOfClient();
        withStoredApplication();
        ArgumentCaptor<ApplicationContextInteraction> created = ArgumentCaptor.forClass(ApplicationContextInteraction.class);

        assertThatGranting(newAction(created, true), grant(clientKey("dpop", proofEntry.toData())))
                .hasStatus(StatusReason.OK.code)
                .whenHandled();

        assertThat(created.getAllValues()).hasSize(1);
    }

    @ValueSource(strings = {"httpsig", "mtls", "jwsd", "jws", "DPoP", ""})
    @ParameterizedTest
    void testClientKeyWithOtherProof(String proof)
    {
        withProofOfClient();
        ArgumentCaptor<ApplicationContextInteraction> created = ArgumentCaptor.forClass(ApplicationContextInteraction.class);

        assertThatGranting(newAction(created, true), grant(clientKey(proof, proofEntry.toData())))
                .hasNoResponse()
                .hasInteractionResponse(InteractionResponse.INVALID_CLIENT, ErrorResponse.INVALID_TOKEN)
                .whenHandled();

        assertThat(created.getAllValues()).isEmpty();
        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testClientKeyOfAnotherKey()
    {
        AccessEntryData other = withProof(SignType.ED25519);
        withProofOfClient();
        ArgumentCaptor<ApplicationContextInteraction> created = ArgumentCaptor.forClass(ApplicationContextInteraction.class);

        assertThatGranting(newAction(created, true), grant(clientKey("dpop", other.toData())))
                .hasNoResponse()
                .hasInteractionResponse(InteractionResponse.INVALID_CLIENT, ErrorResponse.INVALID_TOKEN)
                .whenHandled();

        assertThat(created.getAllValues()).isEmpty();
        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testClientKeyWithoutKeyMaterial()
    {
        withProofOfClient();

        assertThatGranting(newAction(), grant(clientKey("dpop", DataObject.empty().put("kty", "OKP"))))
                .hasNoResponse()
                .hasInteractionResponse(InteractionResponse.INVALID_CLIENT, ErrorResponse.INVALID_TOKEN)
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testClientKeyWithoutJwk()
    {
        withProofOfClient();

        assertThatGranting(newAction(), grant(grant -> grant.getObject("client").put("key", DataObject.empty().put("proof", "dpop"))))
                .hasNoResponse()
                .hasInteractionResponse(InteractionResponse.INVALID_CLIENT, ErrorResponse.INVALID_TOKEN)
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testClientKeyNotObject()
    {
        withProofOfClient();

        assertThatGranting(newAction(), grant(grant -> grant.getObject("client").put("key", "dpop")))
                .hasNoResponse()
                .hasInteractionResponse(InteractionResponse.INVALID_CLIENT, ErrorResponse.INVALID_TOKEN)
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testEmptyFlags()
    {
        withProofOfClient();
        withStoredApplication();
        ArgumentCaptor<ApplicationContextInteraction> created = ArgumentCaptor.forClass(ApplicationContextInteraction.class);

        assertThatGranting(newAction(created, true), grant(token(token -> token.put("flags", DataArray.empty()))))
                .hasStatus(StatusReason.OK.code)
                .whenHandled();

        assertThat(created.getAllValues()).hasSize(1);
    }

    @Test
    void testCreateFailure()
    {
        withProofOfClient();
        withStoredApplication();
        ApplicationInteractionCreateActionImpl action = spy(newAction());
        doAnswer(invocation ->
        {
            ((Runnable) invocation.getArgument(3)).run();
            return null;
        }).when(action).checkClient(any(), any(), any(), any());
        doReturn(failed(new ErrorResponseException(ErrorResponse.MISSING_ACCESS))).when(action).createInteraction(any());

        assertThatGranting(action, grant().toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .whenHandled();
    }

    @Test
    void testClientVerificationRequestsKeys()
    {
        withProofOfClient();
        Application application = withApplication(APPLICATION_ID, OWNER_ID, "app", null, null, "https://93.184.216.34:8443", 0, CALLBACK);
        EmbeddedChannel connection = new EmbeddedChannel();
        connection.attr(JNTImpl.IDENTIFIER).set(jnt);
        SocketManager manager = mock(SocketManager.class);
        when(manager.connect(any(SocketAddress.class))).thenReturn(connection.newSucceededFuture());
        when(api.getSocketManager()).thenReturn(manager);
        Runnable verified = mock(Runnable.class);

        newAction().checkClient(context, channel.attr(ProofObjectManagerImpl.CONTEXT).get(), application, verified);

        ArgumentCaptor<SocketAddress> address = ArgumentCaptor.forClass(SocketAddress.class);
        verify(manager).connect(address.capture());
        assertThat(((InetSocketAddress) address.getValue()).getPort()).isEqualTo(8443);
        Object outbound = connection.readOutbound();
        assertThat(outbound).isInstanceOf(Request.class);
        assertThat(((Request) outbound).getRoute().getCompiledRoute()).isEqualTo(".well-known/jwks.json");
        verify(verified, never()).run();
        connection.finishAndReleaseAll();
        assertThatThrownBy(channel::checkException).isInstanceOf(InteractionResponseException.class);
    }

    @Test
    void testNullArguments()
    {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> newAction().createInteraction(null));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testCreateStatement()
    {
        withJCA();
        ApplicationContextInteraction interaction = mock(ApplicationContextInteraction.class);
        when(interaction.getOwnerId()).thenReturn(OWNER_ID);
        when(interaction.getApplicationId()).thenReturn(APPLICATION_ID);
        when(interaction.getUniqueId()).thenReturn(UUID.fromString("05e4d59d-2366-7152-9eda-876e03dfa88d"));
        when(interaction.getPermissionsRaw()).thenReturn(1L);
        when(interaction.getRedirectUri()).thenReturn(CALLBACK);
        when(interaction.getTimeExpiresAt()).thenReturn(OffsetDateTime.parse("2026-01-01T00:05:00Z"));
        when(interaction.getClientNonce()).thenReturn("client-nonce");
        when(interaction.getFinishNonce()).thenReturn("finish-nonce");
        when(interaction.getMethodHash()).thenReturn("sha-256");
        when(interaction.getUri()).thenReturn("https://iam.example/grant");
        when(interaction.hash()).thenReturn("continue-hash");
        when(interaction.getThumbprint()).thenReturn("client-thumbprint");
        when(interaction.getLabel()).thenReturn("my-token");
        when(interaction.getLabel()).thenReturn("my-token");

        InteractionMappingActionImpl<Void> creation = (InteractionMappingActionImpl<Void>) newAction().createInteraction(interaction);

        assertThat(creation.getContent()).contains("INSERT INTO integrations.interactions");
        assertThatStatementIsBound(creation);
        assertThat(creation.getParams())
                .containsEntry("user_id", OWNER_ID)
                .containsEntry("application_id", APPLICATION_ID)
                .containsEntry("permissions", 1L)
                .containsEntry("redirect_uri", CALLBACK)
                .containsEntry("nonce", "client-nonce")
                .containsEntry("finish", "finish-nonce")
                .containsEntry("method_hash", "sha-256")
                .containsEntry("uri", "https://iam.example/grant")
                .containsEntry("hash", "continue-hash")
                .containsEntry("client_thumbprint", "client-thumbprint")
                .containsEntry("label", "my-token")
                .containsKeys("interaction_id", "expiry");
    }

    private static String thumbprintOf(AccessEntryData entry)
    {
        try (AccessContextData contextData = entry.getContext(AccessContextType.SHA_256))
        {
            return contextData.digest();
        }
        catch (Exception exception)
        {
            throw new IllegalStateException(exception);
        }
    }
}
