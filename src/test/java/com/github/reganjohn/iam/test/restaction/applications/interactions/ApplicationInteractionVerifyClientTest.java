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
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.socket.SocketManager;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryArray;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.api.utils.jose.ProofObjectData;
import com.github.adamorgan.jnt.api.utils.responsebody.JacksonResponseBody;
import com.github.adamorgan.jnt.api.utils.responsebody.ResponseBody;
import com.github.adamorgan.jnt.internal.entities.AbstractEntityBuilder;
import com.github.adamorgan.jnt.internal.JNTImpl;
import com.github.adamorgan.jnt.internal.managers.ProofObjectManagerImpl;
import com.github.adamorgan.jnt.internal.requests.restaction.RestActionImpl;
import com.github.reganjohn.iam.api.entities.Application;
import com.github.reganjohn.iam.api.exceptions.InteractionResponse;
import com.github.reganjohn.iam.api.exceptions.InteractionResponseException;
import com.github.reganjohn.iam.internal.requests.restactions.applications.interactions.ApplicationInteractionCreateActionImpl;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.embedded.EmbeddedChannel;
import org.apache.commons.collections4.map.CaseInsensitiveMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;

import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Collections;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class ApplicationInteractionVerifyClientTest extends RestActionTest
{
    private static final UUID OWNER_ID = UUID.fromString("02b1a26a-f033-7e2f-8ba7-543bd0ac755a");
    private static final UUID APPLICATION_ID = UUID.fromString("04d3c48c-1255-7041-8dc9-765df2ce977c");

    private EmbeddedChannel connection;
    private final AtomicInteger verified = new AtomicInteger();

    @AfterEach
    void closeConnection()
    {
        if (connection != null)
            connection.finishAndReleaseAll();
    }

    private Application newApplication(String origin)
    {
        return withApplication(APPLICATION_ID, OWNER_ID, "app", null, null, origin, 0, origin + "/callback");
    }

    private ProofObjectData proof()
    {
        return channel.attr(ProofObjectManagerImpl.CONTEXT).get();
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

    private void verifyKeys(String origin)
    {
        new ApplicationInteractionCreateActionImpl(api).verifyClient(context, proof(), newApplication(origin), verified::incrementAndGet);
    }

    private RestActionImpl handler()
    {
        return (RestActionImpl) connection.pipeline().last();
    }

    private void deliver(ResponseBody body, int code, AccessEntryArray keys)
    {
        RestActionImpl handler = handler();
        ChannelHandlerContext handlerContext = connection.pipeline().context(handler);
        try (MockedStatic<AbstractEntityBuilder> parsed = mockStatic(AbstractEntityBuilder.class))
        {
            parsed.when(() -> AbstractEntityBuilder.createAccessEntryArray(any(DataObject.class))).thenReturn(keys);

            handler.handleResponse(handlerContext, mock(Request.class), new Response(handlerContext, code, "status", new CaseInsensitiveMap<>(), body));
        }
        catch (Exception exception)
        {
            throw new IllegalStateException(exception);
        }
    }

    private void deliver(int code, AccessEntryArray keys)
    {
        JacksonResponseBody body = mock(JacksonResponseBody.class);
        when(body.isObject()).thenReturn(true);
        when(body.getObject()).thenReturn(DataObject.empty());
        deliver(body, code, keys);
    }

    private void assertRejected()
    {
        assertThatThrownBy(channel::checkException)
                .isInstanceOf(InteractionResponseException.class)
                .satisfies(error -> assertThat(((InteractionResponseException) error).getError()).isEqualTo(InteractionResponse.INVALID_CLIENT));
        assertThat(connection.isOpen()).isFalse();
        assertThat(verified.get()).isZero();
    }

    @Test
    void testConnectFailure()
    {
        withProof(SignType.ED25519);
        connection = new EmbeddedChannel();
        withSocketManager(() -> connection.newFailedFuture(new ConnectException("refused")));

        verifyKeys("https://localhost");

        assertThatThrownBy(channel::checkException).isInstanceOf(InteractionResponseException.class);
        assertThat(verified.get()).isZero();
    }

    @Test
    void testDefaultPort()
    {
        withProof(SignType.ED25519);
        SocketManager manager = withConnection();

        verifyKeys("https://localhost");

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

        verifyKeys("https://localhost:8443");

        ArgumentCaptor<SocketAddress> address = ArgumentCaptor.forClass(SocketAddress.class);
        verify(manager).connect(address.capture());
        assertThat(((InetSocketAddress) address.getValue()).getPort()).isEqualTo(8443);
    }

    @Test
    void testKeysRequest()
    {
        withProof(SignType.ED25519);
        withConnection();

        verifyKeys("https://localhost");

        Object outbound = connection.readOutbound();
        assertThat(outbound).isInstanceOf(Request.class);
        Request request = (Request) outbound;
        assertThat(request.getRoute().getCompiledRoute()).isEqualTo(".well-known/jwks.json");
        assertThat(request.getHeaders().get("Forwarded")).containsExactly("proto=http");
    }

    @Test
    void testVerifiedKey()
    {
        AccessEntryData entry = withProof(SignType.ED25519);
        withConnection();
        verifyKeys("https://localhost");

        deliver(200, new AccessEntryArray(Collections.singletonList(entry)));

        assertThat(verified.get()).isEqualTo(1);
        assertThat(connection.isOpen()).isFalse();
        assertThat((Object) channel.readOutbound()).isNull();
    }

    @Test
    void testKeyOfAnotherClient()
    {
        withProof(SignType.ED25519);
        withConnection();
        verifyKeys("https://localhost");

        deliver(200, new AccessEntryArray(Collections.singletonList(mock(AccessEntryData.class))));

        assertRejected();
    }

    @Test
    void testNoKeys()
    {
        withProof(SignType.ED25519);
        withConnection();
        verifyKeys("https://localhost");

        deliver(200, new AccessEntryArray(Collections.emptyList()));

        assertRejected();
    }

    @ValueSource(ints = {301, 302, 303, 307, 308})
    @ParameterizedTest
    void testRedirectIsRejected(int code)
    {
        withProof(SignType.ED25519);
        withConnection();
        verifyKeys("https://localhost");

        deliver(code, new AccessEntryArray(Collections.emptyList()));

        assertRejected();
    }

    @ValueSource(ints = {400, 401, 404, 500, 503})
    @ParameterizedTest
    void testErrorStatus(int code)
    {
        AccessEntryData entry = withProof(SignType.ED25519);
        withConnection();
        verifyKeys("https://localhost");

        deliver(code, new AccessEntryArray(Collections.singletonList(entry)));

        assertRejected();
    }

    @Test
    void testForeignBody()
    {
        withProof(SignType.ED25519);
        withConnection();
        verifyKeys("https://localhost");

        deliver(mock(ResponseBody.class), 200, new AccessEntryArray(Collections.emptyList()));

        assertRejected();
    }

    @Test
    void testBodyIsNotObject()
    {
        withProof(SignType.ED25519);
        withConnection();
        verifyKeys("https://localhost");
        JacksonResponseBody body = mock(JacksonResponseBody.class);
        when(body.isObject()).thenReturn(false);

        deliver(body, 200, new AccessEntryArray(Collections.emptyList()));

        assertRejected();
    }

    @Test
    void testFailedRequest()
    {
        withProof(SignType.ED25519);
        withConnection();
        verifyKeys("https://localhost");
        RestActionImpl handler = handler();

        try
        {
            handler.handleFailure(connection.pipeline().context(handler), new InvalidResponseException(500, "failure"));
        }
        catch (Exception exception)
        {
            throw new IllegalStateException(exception);
        }

        assertRejected();
    }
}
