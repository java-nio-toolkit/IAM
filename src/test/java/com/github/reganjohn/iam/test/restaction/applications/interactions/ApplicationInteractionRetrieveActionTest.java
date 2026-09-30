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

package com.github.reganjohn.iam.test.restaction.applications.interactions;

import com.github.adamorgan.jnt.api.exceptions.InvalidResponseException;
import com.github.adamorgan.jnt.api.exceptions.MissingAccessException;
import com.github.adamorgan.jnt.api.exceptions.ProofAccessException;
import com.github.adamorgan.jnt.api.managers.AccessEntryManager;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.socket.SocketManager;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextData;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextType;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryArray;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.api.utils.responsebody.BufferedResponseBody;
import com.github.adamorgan.jnt.api.utils.responsebody.JacksonResponseBody;
import com.github.adamorgan.jnt.api.utils.responsebody.ResponseBody;
import com.github.adamorgan.jnt.internal.entities.AbstractEntityBuilder;
import com.github.adamorgan.jnt.internal.managers.AccessEntryManagerImpl;
import com.github.adamorgan.jnt.internal.JNTImpl;
import com.github.adamorgan.jnt.internal.managers.ProofObjectManagerImpl;
import com.github.adamorgan.jnt.internal.requests.restaction.RestActionImpl;
import com.github.reganjohn.iam.api.Permission;
import com.github.reganjohn.iam.api.entities.Application;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.interactions.ApplicationCallbackResponse;
import com.github.reganjohn.iam.internal.requests.restactions.applications.interactions.ApplicationInteractionRetrieveActionImpl;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import com.reganjohn.c4j.api.interactions.response.InteractionCallbackResponse;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.internal.interactions.InteractionImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionContextActionImpl;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.CharsetUtil;
import org.apache.commons.collections4.map.CaseInsensitiveMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;

import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Collections;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class ApplicationInteractionRetrieveActionTest extends RestActionTest
{
    private static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");
    private static final UUID APPLICATION_ID = UUID.fromString("04d3c48c-1255-7041-8dc9-765df2ce977c");
    private static final UUID INTERACTION_ID = UUID.fromString("05e4d59d-2366-7152-9eda-876e03dfa88d");

    private EmbeddedChannel connection;

    private ApplicationInteractionRetrieveActionImpl newAction()
    {
        return new ApplicationInteractionRetrieveActionImpl(api);
    }

    @AfterEach
    void closeConnection()
    {
        if (connection != null)
            connection.finishAndReleaseAll();
    }

    private ApplicationInteractionRetrieveActionImpl newAction(ApplicationCallbackResponse callback)
    {
        ApplicationInteractionRetrieveActionImpl action = spy(newAction());
        InteractionCallbackAction<ApplicationCallbackResponse> retrieval = completed(callback);
        doReturn(retrieval).when(action).retrieveCallbackResponse(APPLICATION_ID, INTERACTION_ID);
        return action;
    }

    private ApplicationCallbackResponse newCallback(String origin)
    {
        Application application = withApplication(APPLICATION_ID, USER_ID, "app", null, null, origin, 0, origin + "/callback");
        InteractionCallbackAction<Application> retrieval = completed(application);
        ApplicationCallbackResponse callback = mock(ApplicationCallbackResponse.class);
        when(callback.getUserId()).thenReturn(USER_ID);
        when(callback.getApplicationId()).thenReturn(APPLICATION_ID);
        when(callback.getInteractionId()).thenReturn(INTERACTION_ID);
        when(callback.getPermissionsRaw()).thenReturn(1L);
        when(callback.getPermissions()).thenReturn(Permission.getPermissions(1L));
        when(callback.retrieveApplication()).thenReturn(retrieval);
        return callback;
    }

    private SocketManager withSocketManager(Supplier<ChannelFuture> connect)
    {
        SocketManager manager = mock(SocketManager.class);
        when(manager.connect(any(SocketAddress.class))).thenAnswer(invocation -> connect.get());
        when(api.getSocketManager()).thenReturn(manager);
        return manager;
    }

    private SocketManager withConnection()
    {
        connection = new EmbeddedChannel();
        connection.attr(JNTImpl.IDENTIFIER).set(jnt);
        return withSocketManager(() -> connection.newSucceededFuture());
    }

    private RestActionImpl interactionHandler()
    {
        return (RestActionImpl) connection.pipeline().last();
    }

    private Response jwks(ChannelHandlerContext ctx, int code)
    {
        JacksonResponseBody body = mock(JacksonResponseBody.class);
        when(body.isObject()).thenReturn(true);
        when(body.getObject()).thenReturn(DataObject.empty());
        return new Response(ctx, code, "status", new CaseInsensitiveMap<>(), body);
    }

    private void deliver(ResponseBody body)
    {
        RestActionImpl handler = interactionHandler();
        ChannelHandlerContext handlerContext = connection.pipeline().context(handler);
        try
        {
            handler.handleResponse(handlerContext, mock(Request.class), new Response(handlerContext, 200, "status", new CaseInsensitiveMap<>(), body));
        }
        catch (Exception exception)
        {
            throw new IllegalStateException(exception);
        }
    }

    static Stream<Arguments> testInvalidIds()
    {
        return Stream.of(
                arguments("application_empty", "", INTERACTION_ID.toString()),
                arguments("application_not_uuid", "not-a-uuid", INTERACTION_ID.toString()),
                arguments("application_too_short", "04d3c48c-1255-7041-8dc9", INTERACTION_ID.toString()),
                arguments("interaction_empty", APPLICATION_ID.toString(), ""),
                arguments("interaction_not_uuid", APPLICATION_ID.toString(), "not-a-uuid"),
                arguments("interaction_too_short", APPLICATION_ID.toString(), "05e4d59d-2366-7152-9eda"),
                arguments("both_invalid", "not-a-uuid", "not-a-uuid"));
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidIds(String name, String applicationId, String interactionId)
    {
        withProof(SignType.ED25519);

        assertThatRequestTo(newAction())
                .withRouteParams(applicationId, interactionId)
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot(name)
                .hasNoResponse()
                .whenHandled();
    }

    @Test
    void testMissingProof()
    {
        assertThatRequestTo(newAction())
                .withRouteParams(APPLICATION_ID.toString(), INTERACTION_ID.toString())
                .hasNoResponse()
                .hasFailureOfType(ProofAccessException.class)
                .whenHandled();
    }

    @Test
    void testUnknownInteraction()
    {
        withProof(SignType.ED25519);
        ApplicationInteractionRetrieveActionImpl action = spy(newAction());
        InteractionCallbackAction<ApplicationCallbackResponse> retrieval = failed(new ErrorResponseException(ErrorResponse.UNKNOWN_INTERACTION));
        doReturn(retrieval).when(action).retrieveCallbackResponse(APPLICATION_ID, INTERACTION_ID);

        assertThatRequestTo(action)
                .withRouteParams(APPLICATION_ID.toString(), INTERACTION_ID.toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testUnknownApplication()
    {
        withProof(SignType.ED25519);
        ApplicationCallbackResponse callback = mock(ApplicationCallbackResponse.class);
        InteractionCallbackAction<Application> retrieval = failed(new ErrorResponseException(ErrorResponse.UNKNOWN_APPLICATION));
        when(callback.retrieveApplication()).thenReturn(retrieval);

        assertThatRequestTo(newAction(callback))
                .withRouteParams(APPLICATION_ID.toString(), INTERACTION_ID.toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();
    }

    @Test
    void testConnectFailure()
    {
        withProof(SignType.ED25519);
        ConnectException failure = new ConnectException("refused");
        connection = new EmbeddedChannel();
        withSocketManager(() -> connection.newFailedFuture(failure));

        assertThatRequestTo(newAction(newCallback("https://localhost")))
                .withRouteParams(APPLICATION_ID.toString(), INTERACTION_ID.toString())
                .hasNoResponse()
                .hasFailureMatching(error -> error == failure)
                .whenHandled();
    }

    @Test
    void testDefaultPort()
    {
        withProof(SignType.ED25519);
        SocketManager manager = withConnection();

        assertThatRequestTo(newAction(newCallback("https://localhost")))
                .withRouteParams(APPLICATION_ID.toString(), INTERACTION_ID.toString())
                .hasNoResponse()
                .whenHandled();

        ArgumentCaptor<SocketAddress> address = ArgumentCaptor.forClass(SocketAddress.class);
        verify(manager).connect(address.capture());
        assertThat(((InetSocketAddress) address.getValue()).getHostString()).isEqualTo("localhost");
        assertThat(((InetSocketAddress) address.getValue()).getPort()).isEqualTo(443);
    }

    @Test
    void testExplicitPort()
    {
        withProof(SignType.ED25519);
        SocketManager manager = withConnection();

        assertThatRequestTo(newAction(newCallback("https://localhost:8443")))
                .withRouteParams(APPLICATION_ID.toString(), INTERACTION_ID.toString())
                .hasNoResponse()
                .whenHandled();

        ArgumentCaptor<SocketAddress> address = ArgumentCaptor.forClass(SocketAddress.class);
        verify(manager).connect(address.capture());
        assertThat(((InetSocketAddress) address.getValue()).getPort()).isEqualTo(8443);
    }

    @Test
    void testKeysRequest()
    {
        withProof(SignType.ED25519);
        withConnection();

        assertThatRequestTo(newAction(newCallback("https://localhost")))
                .withRouteParams(APPLICATION_ID.toString(), INTERACTION_ID.toString())
                .hasNoResponse()
                .whenHandled();

        Object outbound = connection.readOutbound();
        assertThat(outbound).isInstanceOf(Request.class);
        Request request = (Request) outbound;
        assertThat(request.getRoute().getCompiledRoute()).isEqualTo(".well-known/jwks.json");
        assertThat(request.getHeaders().get("Forwarded")).containsExactly("proto=http");
    }

    private void deliver(int code, AccessEntryArray keys, AccessObjectData issued)
    {
        try (MockedStatic<AbstractEntityBuilder> parsed = mockStatic(AbstractEntityBuilder.class);
             MockedStatic<EntityBuilder> built = mockStatic(EntityBuilder.class))
        {
            parsed.when(() -> AbstractEntityBuilder.createAccessEntryArray(any(DataObject.class))).thenReturn(keys);
            built.when(() -> EntityBuilder.createObjectData(anyString(), anyString(), anyString(), any(UUID.class),
                            any(DataArray.class), any(AccessEntryManager.class), any(AccessContextData.class), anyString(),
                            any(AccessEntryManagerImpl.AccessEntrySnapshot.class)))
                    .thenReturn(issued);
            RestActionImpl handler = interactionHandler();
            ChannelHandlerContext handlerContext = connection.pipeline().context(handler);

            handler.handleResponse(handlerContext, mock(Request.class), jwks(handlerContext, code));
        }
        catch (Exception exception)
        {
            throw new IllegalStateException(exception);
        }
    }

    private void handleRequest(ApplicationCallbackResponse callback)
    {
        assertThatRequestTo(newAction(callback))
                .withRouteParams(APPLICATION_ID.toString(), INTERACTION_ID.toString())
                .hasNoResponse()
                .whenHandled();
    }

    @Test
    void testValidInteraction()
    {
        withProof(SignType.ED25519);
        withConnection();
        ApplicationCallbackResponse callback = newCallback("https://localhost");
        InteractionCallbackAction<ApplicationCallbackResponse> deletion = completed(callback);
        when(callback.delete()).thenReturn(deletion);
        AccessEntryData proofEntry = channel.attr(ProofObjectManagerImpl.CONTEXT).get().getEntryData();
        AccessEntryData first = mock(AccessEntryData.class);
        when(first.getUniqueId()).thenReturn("first-key");
        AccessContextData firstContext = mock(AccessContextData.class);
        when(first.getContext(AccessContextType.SHA_256)).thenReturn(firstContext);
        User user = withUser(USER_ID, "alice", null, 0);
        withAccessEntries(user, completed(new AccessEntryArray(Collections.singletonList(first))));
        withRetrieval(USER_ID, completed(user));
        AccessObjectData issued = mock(AccessObjectData.class);
        when(issued.getRaw()).thenReturn(ISSUED_OBJECT);
        when(issued.getScope()).thenReturn(Collections.emptyList());

        handleRequest(callback);
        deliver(200, new AccessEntryArray(Collections.singletonList(proofEntry)), issued);

        Object outbound = channel.readOutbound();
        assertThat(outbound).isInstanceOf(Response.class);
        Response response = (Response) outbound;
        assertThat(response.code).isEqualTo(StatusReason.OK.code);
        BufferedResponseBody body = (BufferedResponseBody) response.getBody();
        String text = body.next().toString(CharsetUtil.UTF_8);
        body.close();
        assertThat(text).isEqualTo("[{\"label\":\"first-key\",\"value\":\"" + ISSUED_OBJECT + "\",\"access\":[]}]");
        verify(callback).delete();
    }

    @Test
    void testProofOfAnotherApplication()
    {
        withProof(SignType.ED25519);
        withConnection();
        ApplicationCallbackResponse callback = newCallback("https://localhost");
        AccessEntryData foreign = mock(AccessEntryData.class);

        handleRequest(callback);
        deliver(200, new AccessEntryArray(Collections.singletonList(foreign)), mock(AccessObjectData.class));

        assertThatThrownBy(channel::checkException).isInstanceOf(MissingAccessException.class);
        assertThat((Object) channel.readOutbound()).isNull();
        verify(callback, never()).delete();
    }

    @Test
    void testRedirectIsRejected()
    {
        withProof(SignType.ED25519);
        withConnection();
        ApplicationCallbackResponse callback = newCallback("https://localhost");

        handleRequest(callback);
        deliver(302, new AccessEntryArray(Collections.emptyList()), mock(AccessObjectData.class));

        assertThatThrownBy(channel::checkException).isInstanceOf(ErrorResponseException.class);
        assertThat(connection.isOpen()).isFalse();
        assertThat((Object) channel.readOutbound()).isNull();
        verify(callback, never()).delete();
    }

    @ValueSource(ints = {400, 404, 500, 503})
    @ParameterizedTest
    void testKeysRequestFailure(int code)
    {
        withProof(SignType.ED25519);
        withConnection();
        ApplicationCallbackResponse callback = newCallback("https://localhost");

        handleRequest(callback);
        deliver(code, new AccessEntryArray(Collections.emptyList()), mock(AccessObjectData.class));

        assertThatThrownBy(channel::checkException).isInstanceOf(ErrorResponseException.class);
        assertThat(connection.isOpen()).isFalse();
        verify(callback, never()).delete();
    }

    @Test
    void testForeignKeysBody()
    {
        withProof(SignType.ED25519);
        withConnection();
        ApplicationCallbackResponse callback = newCallback("https://localhost");

        handleRequest(callback);
        deliver(mock(ResponseBody.class));

        assertThatThrownBy(channel::checkException).isInstanceOf(ErrorResponseException.class);
        assertThat(connection.isOpen()).isFalse();
        verify(callback, never()).delete();
    }

    @Test
    void testKeysBodyIsNotObject()
    {
        withProof(SignType.ED25519);
        withConnection();
        ApplicationCallbackResponse callback = newCallback("https://localhost");
        JacksonResponseBody body = mock(JacksonResponseBody.class);
        when(body.isObject()).thenReturn(false);

        handleRequest(callback);
        deliver(body);

        assertThatThrownBy(channel::checkException).isInstanceOf(ErrorResponseException.class);
        assertThat(connection.isOpen()).isFalse();
        verify(callback, never()).delete();
    }

    @Test
    void testCallbackStatement()
    {
        withJCA();

        InteractionContextActionImpl<?> retrieval = (InteractionContextActionImpl<?>) newAction().retrieveCallbackResponse(APPLICATION_ID, INTERACTION_ID);

        assertThat(retrieval.getContent()).contains("SELECT * FROM integrations.responses", "application_id = ?", "interaction_id = ?");
        assertThat(retrieval.getElements()).containsExactly(APPLICATION_ID, INTERACTION_ID);
    }

    @Test
    @SuppressWarnings("unchecked")
    void testCallbackMissing() throws Exception
    {
        withJCA();
        InteractionContextActionImpl<ApplicationCallbackResponse> retrieval = (InteractionContextActionImpl<ApplicationCallbackResponse>) newAction().retrieveCallbackResponse(APPLICATION_ID, INTERACTION_ID);
        InteractionImpl<ApplicationCallbackResponse> interaction = mock(InteractionImpl.class);
        BufferArray rows = mock(BufferArray.class);
        when(rows.isEmpty()).thenReturn(true);

        retrieval.handleSuccess(mock(InteractionCallbackResponse.class), interaction, rows);

        verify(interaction).onFailure(argThat(error ->
                error instanceof InvalidResponseException
                        && ((InvalidResponseException) error).getErrorCode() == ErrorResponse.UNKNOWN_INTERACTION.getCode()));
    }

    @Test
    void testNullArguments()
    {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> newAction().retrieveCallbackResponse(null, INTERACTION_ID));
        assertThatIllegalArgumentException()
                .isThrownBy(() -> newAction().retrieveCallbackResponse(APPLICATION_ID, null));
    }
}
