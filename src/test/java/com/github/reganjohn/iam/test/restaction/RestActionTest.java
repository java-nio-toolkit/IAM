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
import com.github.adamorgan.jnt.api.utils.requestbody.JacksonRequestBody;
import com.github.adamorgan.jnt.internal.managers.AccessEntryManagerImpl;
import com.github.adamorgan.jnt.internal.managers.AccessOverrideManagerImpl;
import com.github.adamorgan.jnt.internal.managers.ProofObjectManagerImpl;
import com.github.adamorgan.jnt.internal.utils.IOUtil;
import com.github.reganjohn.iam.api.Permission;
import com.github.reganjohn.iam.api.entities.Application;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.entities.PermissionOverride;
import com.github.reganjohn.iam.api.entities.Session;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.entities.Webhook;
import com.github.reganjohn.iam.test.IntegrationTest;
import com.reganjohn.c4j.api.requests.Consistency;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.c4j.internal.JCAImpl;
import com.reganjohn.c4j.internal.requests.objaction.InteractionMappingActionImpl;
import io.netty.channel.ChannelInboundHandler;
import io.netty.util.HashedWheelTimer;
import io.netty.util.concurrent.DefaultThreadFactory;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.AfterEach;
import org.mockito.MockedStatic;

import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
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
        when(action.onSuccess(any())).thenAnswer(invocation ->
        {
            try
            {
                ((Consumer<T>) invocation.getArgument(0)).accept(value);
                return completed(value);
            }
            catch (Throwable failure)
            {
                return failed(failure);
            }
        });
        when(action.flatMap(any(Function.class))).thenAnswer(invocation -> ((Function<T, InteractionCallbackAction<Object>>) invocation.getArgument(0)).apply(value));
        when(action.and(any(), any())).thenAnswer(invocation -> ((InteractionCallbackAction<Object>) invocation.getArgument(0))
                .map(other -> ((BiFunction<T, Object, Object>) invocation.getArgument(1)).apply(value, other)));
        when(action.onErrorMap(any(), any())).thenReturn(action);
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
        when(action.onSuccess(any())).thenAnswer(invocation -> failed(failure));
        when(action.flatMap(any(Function.class))).thenAnswer(invocation -> failed(failure));
        when(action.and(any(), any())).thenAnswer(invocation -> failed(failure));
        when(action.onErrorMap(any(), any())).thenAnswer(invocation -> ((Predicate<Throwable>) invocation.getArgument(0)).test(failure)
                ? completed(((Function<Throwable, Object>) invocation.getArgument(1)).apply(failure))
                : action);
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

    protected void withSession(UUID userId, UUID sessionId, InteractionCallbackAction<Session> result)
    {
        when(api.retrieveSessionById(userId, sessionId)).thenReturn(result);
    }

    protected void withSessions(UUID userId, InteractionCallbackAction<List<Session>> result)
    {
        when(api.retrieveSessions(userId)).thenReturn(result);
    }

    protected void withSessionCount(UUID userId, InteractionCallbackAction<Integer> result)
    {
        when(api.retrieveSessionCount(userId)).thenReturn(result);
    }

    protected void withAccessEntries(User user, InteractionCallbackAction<AccessEntryArray> result)
    {
        when(user.retrieveAccess()).thenReturn(result);
    }

    protected void withAccessEntry(Session session, InteractionCallbackAction<AccessEntryData> result)
    {
        when(session.retrieveAccess()).thenReturn(result);
    }

    protected static Webhook withWebhook(UUID webhookId, UUID ownerId, String name, String avatarId, String url, long scopes, long flags)
    {
        InteractionCallbackAction<Void> deletion = completed(null);
        OffsetDateTime updatedAt = OffsetDateTime.parse("2026-01-01T00:00:00Z");
        Webhook webhook = mock(Webhook.class);
        when(webhook.getUniqueId()).thenReturn(webhookId);
        when(webhook.getOwnerId()).thenReturn(ownerId);
        when(webhook.getName()).thenReturn(name);
        when(webhook.getAvatarId()).thenReturn(avatarId);
        when(webhook.getUrl()).thenReturn(url);
        when(webhook.getScopesRaw()).thenReturn(scopes);
        when(webhook.getFlagsRaw()).thenReturn(flags);
        when(webhook.getTimeUpdated()).thenReturn(updatedAt);
        when(webhook.toData()).thenReturn(DataObject.empty()
                .put("owner_id", ownerId.toString())
                .put("webhook_id", webhookId.toString())
                .put("name", name)
                .put("avatar_id", avatarId)
                .put("url", url)
                .put("scopes", scopes)
                .put("flags", flags)
                .put("updated_at", updatedAt.toString()));
        when(webhook.delete()).thenReturn(deletion);
        return webhook;
    }

    protected void withWebhooks(User user, InteractionCallbackAction<List<Webhook>> result)
    {
        when(user.retrieveWebhooks()).thenReturn(result);
    }

    protected void withWebhooks(UUID userId, InteractionCallbackAction<List<Webhook>> result)
    {
        when(api.retrieveWebhooks(userId)).thenReturn(result);
    }

    protected void withWebhookCount(UUID userId, InteractionCallbackAction<Integer> result)
    {
        when(api.retrieveWebhookCount(userId)).thenReturn(result);
    }

    protected static Application withApplication(UUID applicationId, UUID ownerId, String name, String description, String iconId, String origin, long flags, String... redirectUris)
    {
        InteractionCallbackAction<Void> deletion = completed(null);
        Application application = mock(Application.class);
        when(application.getUniqueId()).thenReturn(applicationId);
        when(application.getOwnerId()).thenReturn(ownerId);
        when(application.getName()).thenReturn(name);
        when(application.getDescription()).thenReturn(description);
        when(application.getIconId()).thenReturn(iconId);
        when(application.getOrigin()).thenReturn(origin);
        when(application.getFlagsRaw()).thenReturn(flags);
        when(application.getRedirectUris()).thenReturn(Arrays.asList(redirectUris));
        when(application.delete()).thenReturn(deletion);
        return application;
    }

    protected void withApplication(User user, UUID applicationId, InteractionCallbackAction<Application> result)
    {
        when(user.retrieveApplicationById(applicationId)).thenReturn(result);
    }

    protected void withApplication(UUID userId, UUID applicationId, InteractionCallbackAction<Application> result)
    {
        when(api.retrieveApplicationById(userId, applicationId)).thenReturn(result);
    }

    protected void withApplications(UUID userId, InteractionCallbackAction<List<Application>> result)
    {
        when(api.retrieveApplications(userId)).thenReturn(result);
    }

    protected void withApplicationCount(UUID userId, InteractionCallbackAction<Integer> result)
    {
        when(api.retrieveApplicationCount(userId)).thenReturn(result);
    }

    protected static PermissionOverride withEntitlement(UUID userId, UUID applicationId, UUID ownerId, long permissions, long flags)
    {
        InteractionCallbackAction<Void> deletion = completed(null);
        PermissionOverride entitlement = mock(PermissionOverride.class);
        when(entitlement.getUserId()).thenReturn(userId);
        when(entitlement.getApplicationId()).thenReturn(applicationId);
        when(entitlement.getOwnerId()).thenReturn(ownerId);
        when(entitlement.getPermissionsRaw()).thenReturn(permissions);
        when(entitlement.getPermissions()).thenReturn(Permission.getPermissions(permissions));
        when(entitlement.getFlagsRaw()).thenReturn(flags);
        when(entitlement.getTimeUpdated()).thenReturn(OffsetDateTime.parse("2026-01-01T00:00:00Z"));
        when(entitlement.delete()).thenReturn(deletion);
        return entitlement;
    }

    protected void withEntitlement(User user, UUID applicationId, InteractionCallbackAction<PermissionOverride> result)
    {
        when(user.retrieveEntitlementById(applicationId)).thenReturn(result);
    }

    protected void withEntitlement(UUID userId, UUID applicationId, InteractionCallbackAction<PermissionOverride> result)
    {
        when(api.retrieveEntitlementById(userId, applicationId)).thenReturn(result);
    }

    protected void withEntitlements(UUID userId, InteractionCallbackAction<List<PermissionOverride>> result)
    {
        when(api.retrieveEntitlements(userId)).thenReturn(result);
    }

    protected List<Object> withEventRecorder()
    {
        List<Object> events = new ArrayList<>();
        ChannelInboundHandler recorder = mock(ChannelInboundHandler.class);
        try
        {
            doAnswer(invocation ->
            {
                events.add(invocation.getArgument(1));
                return null;
            }).when(recorder).userEventTriggered(any(), any());
        }
        catch (Exception exception)
        {
            throw new IllegalStateException(exception);
        }
        channel.pipeline().addLast(recorder);
        return events;
    }

    protected static void assertThatStatementIsBound(InteractionMappingActionImpl<?> action)
    {
        Matcher matcher = Pattern.compile("(?<![\\w:]):([a-z_]+)\\b").matcher(action.getContent());
        Set<String> placeholders = new TreeSet<>();
        while (matcher.find())
            placeholders.add(matcher.group(1));
        assertThat(action.getParams().keySet()).containsAll(placeholders);
    }

    protected static JacksonRequestBody nonObjectBody()
    {
        JacksonRequestBody body = mock(JacksonRequestBody.class);
        when(body.isObject()).thenReturn(false);
        return body;
    }
    protected static String digestOf(String value)
    {
        return digestOf("SHA-256", value);
    }

    protected static String digestOf(String algorithm, String value)
    {
        byte[] digest = new DigestUtils(algorithm).digest(value.getBytes(StandardCharsets.US_ASCII));
        return IOUtil.encodeURL(digest);
    }

    protected static String interactionHashOf(String clientNonce, String finishNonce, String reference, String grantUri)
    {
        return digestOf(String.join("\n", clientNonce, finishNonce, reference, grantUri));
    }
}
