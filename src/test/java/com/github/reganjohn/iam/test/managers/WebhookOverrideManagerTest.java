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

import com.github.adamorgan.jnt.api.ConnectionType;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.requests.Response;
import com.github.adamorgan.jnt.api.socket.SocketManager;
import com.github.adamorgan.jnt.api.utils.MiscUtil;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.requestbody.BufferedRequestBody;
import com.github.adamorgan.jnt.internal.JNTImpl;
import com.github.adamorgan.jnt.internal.requests.restaction.RestActionImpl;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.entities.Webhook;
import com.github.reganjohn.iam.api.events.applications.interactions.InteractionOverrideEvent;
import com.github.reganjohn.iam.api.interactions.ApplicationContextInteraction;
import com.github.reganjohn.iam.internal.managers.WebhookOverrideManagerImpl;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.apache.commons.collections4.map.CaseInsensitiveMap;
import org.mockito.ArgumentCaptor;

import java.net.InetAddress;
import java.util.Collections;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class WebhookOverrideManagerTest extends RestActionTest
{
    private static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");
    private static final UUID WEBHOOK_ID = UUID.fromString("04d3c48c-1255-7041-8dc9-765df2ce977c");

    private SocketManager withEndpoint(String url, ChannelPipeline pipeline)
    {
        Webhook webhook = withWebhook(WEBHOOK_ID, USER_ID, "hook", null, url, 3, 0);
        when(webhook.hasScope(any())).thenReturn(true);
        User user = withUser(USER_ID, "alice", null, 0);
        withWebhooks(user, completed(Collections.singletonList(webhook)));
        withRetrieval(USER_ID, completed(user));

        Channel connected = mock(Channel.class);
        when(connected.pipeline()).thenReturn(pipeline);
        ChannelFuture future = mock(ChannelFuture.class);
        when(future.isSuccess()).thenReturn(true);
        when(future.channel()).thenReturn(connected);
        doAnswer(invocation ->
        {
            ((ChannelFutureListener) invocation.getArgument(0)).operationComplete(future);
            return future;
        }).when(future).addListener(any());

        SocketManager manager = mock(SocketManager.class);
        when(manager.connect(any(InetAddress.class), anyInt())).thenReturn(future);
        when(api.getSocketManager()).thenReturn(manager);
        return manager;
    }

    private void handle()
    {
        ApplicationContextInteraction interaction = mock(ApplicationContextInteraction.class);
        when(interaction.getOwnerId()).thenReturn(USER_ID);
        new WebhookOverrideManagerImpl(api).onGenericEvent(context, new InteractionOverrideEvent(interaction));
    }

    @CsvSource(value = {
            "https://1.1.1.1/hook,hook",
            "https://1.1.1.1/a/b,a/b",
            "https://1.1.1.1/,''",
            "https://1.1.1.1,''",
            "https://1.1.1.1:8443/hook,hook"})
    @ParameterizedTest
    void testConnect(String url, String path) throws Exception
    {
        ChannelPipeline pipeline = mock(ChannelPipeline.class);
        SocketManager manager = withEndpoint(url, pipeline);

        handle();

        ArgumentCaptor<ChannelHandler> handler = ArgumentCaptor.forClass(ChannelHandler.class);
        verify(manager).connect(InetAddress.getByName("1.1.1.1"), url.contains(":8443") ? 8443 : 443);
        verify(manager, never()).connect(anyString(), anyInt());
        verify(pipeline).addLast(handler.capture());
        assertThat(((RestActionImpl) handler.getValue()).getBaseRoute().get(0).compile().getCompiledRoute()).isEqualTo(path);
    }

    private EmbeddedChannel connect(ChannelHandler... handlers)
    {
        ChannelPipeline pipeline = mock(ChannelPipeline.class);
        withEndpoint("https://1.1.1.1/hook", pipeline);

        handle();

        ArgumentCaptor<ChannelHandler> handler = ArgumentCaptor.forClass(ChannelHandler.class);
        verify(pipeline).addLast(handler.capture());
        EmbeddedChannel webhook = new EmbeddedChannel(handlers);
        webhook.attr(JNTImpl.IDENTIFIER).set(jnt);
        webhook.pipeline().addLast(handler.getValue());
        return webhook;
    }

    @ParameterizedTest
    @ValueSource(ints = {204, 302, 500})
    void testResponseClosesChannel(int code)
    {
        when(jnt.getConnectionType()).thenReturn(ConnectionType.CLIENT);
        EmbeddedChannel webhook = connect();
        Request request = webhook.readOutbound();
        webhook.attr(Request.IDENTIFIER).set(request);

        webhook.writeInbound(new Response(webhook.pipeline().firstContext(), code, "Reason", new CaseInsensitiveMap<>(), null));

        assertThat(webhook.isActive()).isFalse();
        assertThat(request.getBody()).isNull();
    }

    @Test
    void testWriteFailure()
    {
        FailingWriteHandler failing = new FailingWriteHandler();
        EmbeddedChannel webhook = connect(failing);

        assertThat(webhook.isActive()).isFalse();
        assertThat(((Request) failing.message).getBody()).isNull();
    }

    @Test
    void testAcceptPayload()
    {
        EmbeddedChannel webhook = connect();
        Request request = webhook.readOutbound();
        DataObject body = DataObject.fromJson(((BufferedRequestBody) request.getBody()).next());
        request.closeResource();

        assertThat(body.getObject("interaction").getString("type")).isEqualTo("ACCEPTED");
        assertThat(body.getObject("interaction").getString("user_id")).isEqualTo(USER_ID.toString());
        assertThat(body.getString("webhook_id")).isEqualTo(WEBHOOK_ID.toString());
        assertThat(MiscUtil.isUUID(body.getString("unique_id"))).isTrue();
        assertThat(request.getHeaders()).containsKey("Host");
    }

    @Test
    void testUnsafeUrl()
    {
        SocketManager manager = withEndpoint("https://127.0.0.1/hook", mock(ChannelPipeline.class));

        handle();

        verify(manager, never()).connect(any(InetAddress.class), anyInt());
        verify(manager, never()).connect(anyString(), anyInt());
    }
}
