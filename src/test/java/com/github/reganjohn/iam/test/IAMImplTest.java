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

package com.github.reganjohn.iam.test;

import com.github.adamorgan.jnt.api.ConnectionType;
import com.github.adamorgan.jnt.api.JNTBuilder;
import com.github.adamorgan.jnt.api.exceptions.ProofAccessException;
import com.github.adamorgan.jnt.api.managers.AccessEntryManager;
import com.github.adamorgan.jnt.api.requests.Request;
import com.github.adamorgan.jnt.api.socket.DefaultSocketManagerBuilder;
import com.github.adamorgan.jnt.api.socket.SocketManager;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextData;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextType;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.api.utils.jose.ProofObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessEntryManagerImpl;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.managers.ProofObjectManagerImpl;
import com.github.adamorgan.jnt.internal.utils.IOUtil;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.entities.Session;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.requests.Routes;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.entities.SessionImpl;
import com.github.reganjohn.iam.internal.managers.AccessSignatureManagerImpl;
import com.github.reganjohn.iam.internal.managers.GlobalAccessManagerImpl;
import com.github.reganjohn.iam.internal.managers.TokenVerifyManagerImpl;
import com.reganjohn.c4j.api.JCA;
import com.reganjohn.c4j.api.JCABuilder;
import com.reganjohn.c4j.api.interactions.response.InteractionCallbackResponse;
import com.reganjohn.c4j.api.requests.Consistency;
import com.reganjohn.c4j.api.utils.data.BufferArray;
import com.reganjohn.c4j.api.utils.data.BufferObject;
import com.reganjohn.c4j.internal.JCAImpl;
import com.reganjohn.c4j.internal.interactions.InteractionImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionContextActionImpl;
import com.reganjohn.jdt.api.JDTBuilder;
import io.netty.channel.ChannelHandler;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.collections4.map.CaseInsensitiveMap;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.MockedStatic;

import java.security.KeyPairGenerator;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Answers.RETURNS_SELF;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

public class IAMImplTest extends IntegrationTest
{
    private static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");
    private static final UUID SESSION_ID = UUID.fromString("04d3c48c-1255-7041-8dc9-765df2ce977c");
    private static final String THUMBPRINT = "thumbprint";
    private static final String TOKEN = "header.payload.signature";

    @Test
    void testShutdown() throws InterruptedException
    {
        GlobalAccessManagerImpl manager = mock(GlobalAccessManagerImpl.class);
        SocketManager socketManager = mock(SocketManager.class);
        JCA jca = mock(JCA.class);
        when(api.getAccessManager()).thenReturn(manager);
        when(api.getSocketManager()).thenReturn(socketManager);
        when(api.getJCA()).thenReturn(jca);
        doCallRealMethod().when(api).shutdown();

        api.shutdown();

        InOrder order = inOrder(jnt, manager, socketManager, jca);
        order.verify(jnt).shutdown();
        order.verify(jnt).awaitShutdown(30, TimeUnit.SECONDS);
        order.verify(manager).shutdown();
        order.verify(socketManager).shutdown();
        order.verify(jca).shutdown();
    }

    @Test
    void testShutdownInterrupted() throws InterruptedException
    {
        GlobalAccessManagerImpl manager = mock(GlobalAccessManagerImpl.class);
        SocketManager socketManager = mock(SocketManager.class);
        JCA jca = mock(JCA.class);
        when(api.getAccessManager()).thenReturn(manager);
        when(api.getSocketManager()).thenReturn(socketManager);
        when(api.getJCA()).thenReturn(jca);
        when(jnt.awaitShutdown(30, TimeUnit.SECONDS)).thenThrow(new InterruptedException());
        doCallRealMethod().when(api).shutdown();

        api.shutdown();

        assertThat(Thread.interrupted()).isTrue();
        InOrder order = inOrder(manager, socketManager, jca);
        order.verify(manager).shutdown();
        order.verify(socketManager).shutdown();
        order.verify(jca).shutdown();
    }

    @Test
    void testShutdownAccessManager()
    {
        GlobalAccessManagerImpl manager = new GlobalAccessManagerImpl(api, SignType.ED25519, 2, 15, TimeUnit.DAYS, "https://localhost.com");

        manager.shutdown();

        assertThatIllegalStateException().isThrownBy(() -> manager.enqueue(0));
    }

    @SuppressWarnings("unchecked")
    private InteractionContextActionImpl<Session> retrieveSession()
    {
        JCAImpl jca = mock(JCAImpl.class);
        when(jca.getConsistency()).thenReturn(Consistency.QUORUM);
        when(api.getJCA()).thenReturn(jca);
        when(api.retrieveSessionById(any(), any())).thenCallRealMethod();
        return (InteractionContextActionImpl<Session>) api.retrieveSessionById(USER_ID, SESSION_ID);
    }

    private static BufferArray rowsOf(BufferObject... rows)
    {
        BufferArray array = mock(BufferArray.class);
        when(array.isEmpty()).thenReturn(rows.length == 0);
        if (rows.length > 0)
            when(array.getObject(0)).thenReturn(rows[0]);
        when(array.iterator()).thenAnswer(invocation -> Arrays.asList(rows).iterator());
        return array;
    }

    @SuppressWarnings("unchecked")
    private void assertUnknownSession(BufferArray rows) throws Exception
    {
        InteractionImpl<Session> interaction = mock(InteractionImpl.class);

        retrieveSession().handleSuccess(mock(InteractionCallbackResponse.class), interaction, rows);

        ArgumentCaptor<Throwable> failure = ArgumentCaptor.forClass(Throwable.class);
        verify(interaction).onFailure(failure.capture());
        assertThat(failure.getValue()).isInstanceOf(ErrorResponseException.class);
        assertThat(((ErrorResponseException) failure.getValue()).getErrorCode()).isEqualTo(ErrorResponse.UNKNOWN_SESSION.getCode());
        verify(interaction, never()).onSuccess(any());
    }

    @Test
    void testSessionStatement()
    {
        InteractionContextActionImpl<Session> retrieval = retrieveSession();

        assertThat(retrieval.getContent()).contains("SELECT * FROM users.sessions", "user_id = ?", "session_id = ?");
        assertThat(retrieval.getElements()).containsExactly(USER_ID, SESSION_ID);
    }

    @Test
    @SuppressWarnings("unchecked")
    void testSessionById() throws Exception
    {
        BufferObject row = mock(BufferObject.class);
        SessionImpl session = mock(SessionImpl.class);
        EntityBuilder builder = mock(EntityBuilder.class);
        when(builder.createSession(row)).thenReturn(session);
        when(api.getEntityBuilder()).thenReturn(builder);
        InteractionImpl<Session> interaction = mock(InteractionImpl.class);

        retrieveSession().handleSuccess(mock(InteractionCallbackResponse.class), interaction, rowsOf(row));

        verify(interaction).onSuccess(session);
    }

    @Test
    void testMissingSessionById() throws Exception
    {
        assertUnknownSession(rowsOf());
    }

    @Test
    void testDeletedSessionById() throws Exception
    {
        BufferObject row = mock(BufferObject.class);
        when(row.getLong("flags", 0)).thenReturn(1L << 34);

        assertUnknownSession(rowsOf(row));
    }

    private void withSessionRequest() throws Exception
    {
        AccessEntryManager entries = mock(AccessEntryManager.class);
        when(entries.hasAccess(any(), any(), anyString(), anyString(), anyString())).thenReturn(true);
        AccessObjectData access = mock(AccessObjectData.class);
        when(access.getSubject()).thenReturn(USER_ID.toString());
        when(access.getThumbprint()).thenReturn(THUMBPRINT);
        when(access.getBody()).thenReturn(DataObject.empty().put("cnf", DataObject.empty().put("jkt", THUMBPRINT)));
        AccessContextData contextData = mock(AccessContextData.class);
        when(contextData.digest()).thenReturn(THUMBPRINT);
        AccessEntryData entry = mock(AccessEntryData.class);
        when(entry.getPublic()).thenReturn(KeyPairGenerator.getInstance("EC").generateKeyPair().getPublic());
        ProofObjectData proof = mock(ProofObjectData.class);
        when(proof.getAccessTokenHash()).thenReturn(IOUtil.encodeURL(DigestUtils.sha256(TOKEN)));
        when(proof.getContext(AccessContextType.SHA_256)).thenReturn(contextData);
        when(proof.getEntryData()).thenReturn(entry);
        channel.attr(AccessEntryManagerImpl.IDENTIFIER).set(entries);
        channel.attr(AccessOverrideManagerImpl.CONTEXT).set(access);
        channel.attr(ProofObjectManagerImpl.CONTEXT).set(proof);
        when(jnt.getConnectionType()).thenReturn(ConnectionType.SERVER);
    }

    @Test
    void testUnsignedSessionRequest() throws Exception
    {
        JCA jca = mock(JCA.class);
        when(jca.awaitReady()).thenReturn(jca);
        JCABuilder jcaBuilder = mock(JCABuilder.class, RETURNS_SELF);
        when(jcaBuilder.build()).thenReturn(jca);
        JNTBuilder builder = mock(JNTBuilder.class, RETURNS_SELF);
        IAMImpl iam;
        try (MockedStatic<JCABuilder> jcaBuilders = mockStatic(JCABuilder.class);
             MockedStatic<JDTBuilder> jdtBuilders = mockStatic(JDTBuilder.class);
             MockedStatic<DefaultSocketManagerBuilder> socketBuilders = mockStatic(DefaultSocketManagerBuilder.class);
             MockedStatic<JNTBuilder> builders = mockStatic(JNTBuilder.class))
        {
            jcaBuilders.when(() -> JCABuilder.create(anyString(), anyInt())).thenReturn(jcaBuilder);
            jdtBuilders.when(() -> JDTBuilder.create(any())).thenReturn(mock(JDTBuilder.class, RETURNS_SELF));
            socketBuilders.when(DefaultSocketManagerBuilder::create).thenReturn(mock(DefaultSocketManagerBuilder.class, RETURNS_SELF));
            builders.when(() -> JNTBuilder.create(anyInt())).thenReturn(builder);
            iam = new IAMImpl(8080, "https://localhost.com");
        }
        try
        {
            ArgumentCaptor<Object> listeners = ArgumentCaptor.forClass(Object.class);
            verify(builder, atLeastOnce()).addEventListeners(listeners.capture());
            ChannelHandler[] handlers = listeners.getAllValues().stream()
                    .filter(listener -> listener instanceof AccessSignatureManagerImpl || listener instanceof TokenVerifyManagerImpl)
                    .toArray(ChannelHandler[]::new);
            withSessionRequest();
            channel.pipeline().addLast(handlers);
            clearInvocations(jca);
            CaseInsensitiveMap<String, Collection<String>> headers = new CaseInsensitiveMap<>();
            headers.put("Host", Collections.singletonList("iam.example"));
            headers.put("Authorization", Collections.singletonList("DPoP " + TOKEN));
            Request request = new Request(context, Routes.Self.DELETE_SELF.compile(), headers);

            assertThat(handlers).hasSize(2);
            assertThatThrownBy(() -> channel.writeInbound(request)).isInstanceOf(ProofAccessException.class);
            verifyNoInteractions(jca);
        }
        finally
        {
            ((GlobalAccessManagerImpl) iam.getAccessManager()).shutdown();
        }
    }
}
