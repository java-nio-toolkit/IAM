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

package com.github.reganjohn.iam.test.restaction;

import com.github.adamorgan.jnt.api.managers.AccessEntryManager;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextData;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextType;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryArray;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.api.utils.jose.ProofObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessEntryManagerImpl;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.managers.ProofObjectManagerImpl;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.entities.Session;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.test.IntegrationTest;
import com.reganjohn.c4j.api.requests.Consistency;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.c4j.internal.JCAImpl;
import io.netty.util.HashedWheelTimer;
import io.netty.util.concurrent.DefaultThreadFactory;
import org.junit.jupiter.api.AfterEach;
import org.mockito.MockedStatic;

import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Function;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class RestActionTest extends IntegrationTest
{
    protected static final String THUMBPRINT = "thumbprint";
    protected static final String ISSUED_OBJECT = "issued.access.object";

    private HashedWheelTimer timer;

    protected void withProof()
    {
        AccessContextData contextData = mock(AccessContextData.class);
        when(contextData.digest()).thenReturn(THUMBPRINT);

        install(newManager(SignType.ES256), contextData);
    }

    protected AccessEntryData withProof(SignType type)
    {
        AccessEntryManagerImpl manager = newManager(type);
        AccessEntryData entry = manager.getCurrentOrder();
        install(manager, entry.getContext(AccessContextType.SHA_256));
        return entry;
    }

    private AccessEntryManagerImpl newManager(SignType type)
    {
        if (timer == null)
            timer = new HashedWheelTimer(new DefaultThreadFactory("iam-test-timer", true), 1, TimeUnit.SECONDS);
        return new AccessEntryManagerImpl(timer, type, 1, 1, TimeUnit.HOURS, Collections.singletonList("iam.test"));
    }

    private void install(AccessEntryManagerImpl manager, AccessContextData contextData)
    {
        ProofObjectData proof = mock(ProofObjectData.class);
        when(proof.getContext(AccessContextType.SHA_256)).thenReturn(contextData);
        when(proof.getEntryData()).thenReturn(manager.getCurrentOrder());

        channel.attr(ProofObjectManagerImpl.CONTEXT).set(proof);
        channel.attr(AccessEntryManagerImpl.IDENTIFIER).set(manager);
    }

    @AfterEach
    void stopTimer()
    {
        if (timer != null)
            timer.stop();
        timer = null;
    }

    protected void withJCA()
    {
        JCAImpl jca = mock(JCAImpl.class);
        when(jca.getConsistency()).thenReturn(Consistency.QUORUM);
        when(api.getJCA()).thenReturn(jca);
    }

    protected static void withIssuedObject(MockedStatic<EntityBuilder> builder)
    {
        withIssuedObject(builder, null);
    }

    protected static void withIssuedObject(MockedStatic<EntityBuilder> builder, String subject)
    {
        AccessObjectData issued = mock(AccessObjectData.class);
        when(issued.getRaw()).thenReturn(ISSUED_OBJECT);
        when(issued.getSubject()).thenReturn(subject);
        builder.when(() -> EntityBuilder.createObjectData(anyString(), anyString(), anyString(),
                        any(AccessEntryManager.class), any(AccessContextData.class), anyString(),
                        any(AccessEntryManagerImpl.AccessEntrySnapshot.class)))
                .thenReturn(issued);
    }
    protected void withAccess(UUID subject)
    {
        withAccess(subject.toString());
    }

    protected void withAccess(String subject)
    {
        AccessObjectData access = mock(AccessObjectData.class);
        when(access.getSubject()).thenReturn(subject);
        channel.attr(AccessOverrideManagerImpl.CONTEXT).set(access);
    }

    protected static User withUser(UUID id, String name, String avatarId, long flags)
    {
        InteractionCallbackAction<Void> deletion = completed(null);
        User user = mock(User.class);
        when(user.getUniqueId()).thenReturn(id);
        when(user.getName()).thenReturn(name);
        when(user.getAvatarId()).thenReturn(avatarId);
        when(user.getFlagsRaw()).thenReturn(flags);
        when(user.delete()).thenReturn(deletion);
        return user;
    }

    @SuppressWarnings("unchecked")
    protected static <T> InteractionCallbackAction<T> completed(T value)
    {
        InteractionCallbackAction<T> action = mock(InteractionCallbackAction.class);
        doAnswer(invocation ->
        {
            ((Consumer<T>) invocation.getArgument(0)).accept(value);
            return null;
        }).when(action).queue(any(), any());
        when(action.map(any())).thenAnswer(invocation -> completed(((Function<T, Object>) invocation.getArgument(0)).apply(value)));
        when(action.flatMap(any(Function.class))).thenAnswer(invocation -> ((Function<T, InteractionCallbackAction<Object>>) invocation.getArgument(0)).apply(value));
        return action;
    }

    @SuppressWarnings("unchecked")
    protected static <T> InteractionCallbackAction<T> failed(Throwable failure)
    {
        InteractionCallbackAction<T> action = mock(InteractionCallbackAction.class);
        doAnswer(invocation ->
        {
            ((Consumer<Throwable>) invocation.getArgument(1)).accept(failure);
            return null;
        }).when(action).queue(any(), any());
        when(action.map(any())).thenAnswer(invocation -> failed(failure));
        when(action.flatMap(any(Function.class))).thenAnswer(invocation -> failed(failure));
        return action;
    }
    protected void withRetrieval(UUID id, InteractionCallbackAction<User> retrieval)
    {
        when(api.retrieveUserById(id)).thenReturn(retrieval);
    }

    protected void withRetrieval(InteractionCallbackAction<User> retrieval)
    {
        when(api.retrieveUserById(any())).thenReturn(retrieval);
    }

    protected static String body(Object... fields)
    {
        DataObject body = DataObject.empty();
        for (int i = 0; i < fields.length; i += 2)
            body.put((String) fields[i], fields[i + 1]);
        return body.toString();
    }

    protected static DataObject session(Object... fields)
    {
        DataObject session = DataObject.empty();
        for (int i = 0; i < fields.length; i += 2)
            session.put((String) fields[i], fields[i + 1]);
        return session;
    }
    protected static Session withSession(UUID sessionId, UUID userId, String userAgent, long flags, String thumbprint)
    {
        InteractionCallbackAction<Void> deletion = completed(null);
        Session session = mock(Session.class);
        when(session.getUniqueId()).thenReturn(sessionId);
        when(session.getUserId()).thenReturn(userId);
        when(session.getUserAgent()).thenReturn(userAgent);
        when(session.getFlagsRaw()).thenReturn(flags);
        when(session.getThumbprint()).thenReturn(thumbprint);
        when(session.delete()).thenReturn(deletion);
        return session;
    }

    protected void withSession(User user, UUID sessionId, InteractionCallbackAction<Session> result)
    {
        when(user.retrieveSessionById(sessionId)).thenReturn(result);
    }

    protected void withSessions(User user, InteractionCallbackAction<List<Session>> result)
    {
        when(user.retrieveSessions()).thenReturn(result);
    }

    protected void withSessionCount(User user, InteractionCallbackAction<Integer> result)
    {
        when(user.retrieveSessionCount()).thenReturn(result);
    }

    protected void withAccessEntries(User user, InteractionCallbackAction<AccessEntryArray> result)
    {
        when(user.retrieveAccess()).thenReturn(result);
    }

    protected void withAccessEntry(Session session, InteractionCallbackAction<AccessEntryData> result)
    {
        when(session.retrieveAccess()).thenReturn(result);
    }
}
