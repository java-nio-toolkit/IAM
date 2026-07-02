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

package com.github.reganjohn.iam.internal;

import com.github.adamorgan.jnt.api.ConnectionType;
import com.github.adamorgan.jnt.api.JNT;
import com.github.adamorgan.jnt.api.JNTBuilder;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.internal.JNTImpl;
import com.github.adamorgan.jnt.internal.handle.classic.ClassicReceiveHandlerImpl;
import com.github.adamorgan.jnt.internal.managers.*;
import com.github.adamorgan.jnt.internal.requests.restaction.AccessEntryActionImpl;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.reganjohn.iam.archive.AdaMorganClientV2;
import com.github.reganjohn.iam.internal.managers.ContentSecurityOverrideManagerImpl;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.internal.managers.ErrorObjectManagerImpl;
import com.github.reganjohn.iam.internal.managers.GlobalAccessEntryManagerImpl;
import com.github.reganjohn.iam.internal.requests.restactions.self.SelfUserCreateActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.self.SelfUserDeleteActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.self.SelfUserEditActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.self.SelfUserRetrieveActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.session.*;
import com.reganjohn.jact.api.JACT;
import com.reganjohn.jact.api.JACTBuilder;
import com.reganjohn.jact.api.requests.Consistency;
import com.reganjohn.jact.api.requests.objaction.InteractionContextAction;
import com.reganjohn.jact.api.requests.objaction.InteractionMappingAction;
import com.reganjohn.jact.api.utils.Compression;
import com.reganjohn.jact.api.utils.data.BufferArray;
import com.reganjohn.jact.internal.JACTImpl;
import com.reganjohn.jact.internal.interactions.InteractionImpl;
import com.reganjohn.jact.internal.interactions.response.InteractionCallbackResponseImpl;
import com.reganjohn.jact.internal.managers.SecretAccessManagerImpl;
import com.reganjohn.jact.internal.requests.objaction.InteractionContextActionImpl;
import com.reganjohn.jact.internal.requests.objaction.InteractionMappingActionImpl;
import com.reganjohn.jact.internal.utils.InteractionUtil;
import com.github.reganjohn.iam.api.entities.Session;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.internal.requests.restactions.UserRetrieveActionImpl;
import com.github.reganjohn.iam.api.utils.ClassLoader;
import com.github.reganjohn.iam.api.utils.sessions.SessionCreateData;
import com.github.reganjohn.iam.api.utils.sessions.SessionEditData;
import com.github.reganjohn.iam.api.utils.users.UserCreateData;
import com.github.reganjohn.iam.api.utils.users.UserEditData;
import io.netty.util.ResourceLeakDetector;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.security.Security;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class IAMImpl
{
    static
    {
        if (Security.getProvider("BC") == null)
            Security.addProvider(new BouncyCastleProvider());
        ResourceLeakDetector.setLevel(ResourceLeakDetector.Level.DISABLED);
    }

    public static final Map<UUID, User> users = new ConcurrentHashMap<>();
    public static final Map<UUID, Session> sessions = new ConcurrentHashMap<>();

    private final JNT api;
    private final JACT jact;

    public static void main(String[] args) throws Exception
    {
        String host = "localhost";
        int port = 8080;
        new IAMImpl(host, port);
    }

    public static JACT buildInstance()
    {
        return JACTBuilder.create("localhost", 9042)
                .setApplicationName("Test Client")
                .setProtocolVersion(5)
                .addEventListener(new SecretAccessManagerImpl("cassandra", "cassandra"))
                .setCompression(Compression.LZ4)
                .setDefaultConsistency(Consistency.QUORUM)
                .build();
    }

    public IAMImpl(String host, int port) throws Exception
    {
        List<String> audiences = Collections.singletonList("https://localhost.com");
        this.jact = buildInstance();
        this.api = JNTBuilder.create(host, port, ConnectionType.SERVER)
                .addEventListenerProvider(ClassicReceiveHandlerImpl::new)
                .addEventListeners(new ClockObjectManagerImpl())
                .addEventListeners(new DigestAccessManagerImpl())
                .addEventListeners(new DigestObjectManagerImpl())
                .addEventListeners(new OriginAccessManagerImpl())
                .addEventListeners(new CacheObjectManagerImpl())
                .addEventListeners(new CookieObjectManagerImpl())

                .addEventListeners(new ContentSecurityOverrideManagerImpl())
                .addEventListeners(new GlobalAccessEntryManagerImpl(this, SignType.EDDSA, 2, 6, TimeUnit.SECONDS, audiences))
                .addEventListeners(new ProofObjectManagerImpl(60, 15, true))
                .addEventListeners(new ProofOverrideManagerImpl())
                .addEventListeners(new ProofCryptoManagerImpl())
                .addEventListeners(new ProofPresenceManagerImpl())

                .addEventListenerProvider(ClassicSessionObjectManagerImpl::new)
                .addEventListenerProvider(ContentEncodingManagerImpl::new)
                .addEventListenerProvider(ContentObjectManagerImpl::new)
                //.addEventListenerProvider(() -> new SequentialRestRateLimiter(10, 10, TimeUnit.SECONDS, "user"))

                .addEventListeners(new AccessEntryActionImpl())

                .addEventListenerProvider(() -> new UserRetrieveActionImpl(this))

                .addEventListenerProvider(() -> new SelfUserCreateActionImpl(this))
                .addEventListenerProvider(() -> new SelfUserRetrieveActionImpl(this))
                .addEventListenerProvider(() -> new SelfUserDeleteActionImpl(this))
                .addEventListenerProvider(() -> new SelfUserEditActionImpl(this))
                .addEventListenerProvider(() -> new SessionPaginationActionImpl(this))
                .addEventListenerProvider(() -> new SessionRetrieveActionImpl(this))
                .addEventListenerProvider(() -> new SessionCreateActionImpl(this))
                .addEventListenerProvider(() -> new SessionEditActionImpl(this))
                .addEventListenerProvider(() -> new SessionUpdateActionImpl(this))
                .addEventListenerProvider(() -> new SessionDeleteActionImpl(this))
                .addEventListenerProvider(() -> new SessionLogoutActionImpl(this))

                .addEventListeners(new ErrorObjectManagerImpl(false))
                .build();

        TimeUnit.SECONDS.sleep(2);

        AdaMorganClientV2 client = new AdaMorganClientV2();
        client.startTest();
    }

    @Nonnull
    public JNTImpl getJNT()
    {
        return (JNTImpl) api;
    }

    @Nonnull
    public JACTImpl getJACT()
    {
        return (JACTImpl) jact;
    }

    @Nonnull
    @CheckReturnValue
    public InteractionContextAction<User> retrieveUserById(@Nonnull UUID id)
    {
        Checks.notNull(id, "ID");
        return new InteractionContextActionImpl<>(jact, "SELECT * FROM users.accounts WHERE user_id = ?", Collections.singletonList(id))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<User> request, @Nonnull BufferArray array)
            {
                if (!array.isEmpty())
                    request.onSuccess(EntityBuilder.createUser(array.getObject(0)));
                else
                    request.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_USER));
            }
        };
    }

    @Nonnull
    @CheckReturnValue
    public InteractionMappingAction<Void> createUser(@Nonnull UserCreateData user)
    {
        Checks.notNull(user, "User");
        return createUser(user.toMap());
    }

    @Nonnull
    @CheckReturnValue
    private InteractionMappingAction<Void> createUser(@Nonnull Map<String, Object> map)
    {
        Checks.notEmpty(map, "Map");
        return new InteractionMappingActionImpl<>(jact, ClassLoader.getResourceAsString("create_account.cql"), map)
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Void> request, @Nonnull BufferArray array)
            {
                if (array.isEmpty())
                    request.onSuccess(null);
                else
                    request.onFailure(new ErrorResponseException(ErrorResponse.SESSION_ALREADY_EXISTS));
            }
        };
    }

    @Nonnull
    @CheckReturnValue
    public InteractionMappingAction<Void> deleteUserById(@Nonnull UUID userId)
    {
        Checks.notNull(userId, "ID");
        return new InteractionMappingActionImpl<>(jact, ClassLoader.getResourceAsString("delete_account.cql"), Collections.singletonMap("user_id", userId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Void> request, @Nonnull BufferArray array)
            {
                if (!array.isEmpty())
                    request.onSuccess(null);
                else
                    request.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_USER));
            }
        };
    }

    @Nonnull
    @CheckReturnValue
    public InteractionContextAction<List<Session>> retrieveSessions(@Nonnull UUID userId)
    {
        Checks.notNull(userId, "ID");
        return new InteractionContextActionImpl<>(jact, "SELECT * FROM users.sessions WHERE user_id = ?", Collections.singletonList(userId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<List<Session>> interaction,
                                      @Nonnull BufferArray array) throws Exception
            {
                interaction.onSuccess(array.isEmpty() ? Collections.emptyList() : EntityBuilder.createSessions(array));
            }
        };
    }

    @Nonnull
    @CheckReturnValue
    public InteractionContextAction<Session> retrieveSessionById(@Nonnull UUID userId, @Nonnull UUID sessionId)
    {
        Checks.notNull(userId, "User ID");
        Checks.notNull(sessionId, "Session ID");
        return new InteractionContextActionImpl<>(jact, "SELECT * FROM users.sessions WHERE user_id = ? AND session_id = ?", Arrays.asList(userId, sessionId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Session> interaction,
                                      @Nonnull BufferArray array) throws Exception
            {
                if (array.isEmpty())
                    interaction.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_SESSION));
                else
                    interaction.onSuccess(EntityBuilder.createSession(array.getObject(0)));
            }
        };

    }

    @Nonnull
    public InteractionMappingAction<Void> createSession(@Nonnull SessionCreateData session)
    {
        return createSession(session.toMap());
    }

    @Nonnull
    @CheckReturnValue
    public InteractionMappingAction<Void> createSession(@Nonnull Map<String, Object> map)
    {
        Checks.notEmpty(map, "Map");
        String content = Helpers.format("INSERT INTO users.sessions (%s) VALUES (%s) IF NOT EXISTS",
                Helpers.join(", ", map.keySet()),
                Helpers.join(", ", InteractionUtil.split(map.keySet(), true)));
        return new InteractionMappingActionImpl<>(jact, content, map)
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Void> request, @Nonnull BufferArray array)
            {
                if (InteractionUtil.isDone(array))
                    request.onSuccess(null);
                else
                    request.onFailure(new ErrorResponseException(ErrorResponse.SESSION_ALREADY_EXISTS));
            }
        };
    }

    @Nonnull
    @CheckReturnValue
    public InteractionContextAction<Integer> retrieveSessionCount(@Nonnull UUID userId)
    {
        Checks.notNull(userId, "ID");
        return new InteractionContextActionImpl<>(jact, "SELECT COUNT(*) FROM users.sessions WHERE user_id = ?", Collections.singletonList(userId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Integer> request, @Nonnull BufferArray array)
            {
                request.onSuccess((int) InteractionUtil.count(array));
            }
        };
    }

    @Nonnull
    @CheckReturnValue
    public InteractionMappingAction<Void> editSession(@Nonnull SessionEditData session)
    {
        Checks.notNull(session, "Session");
        String content = Helpers.format("UPDATE users.sessions SET %s WHERE user_id = :user_id AND session_id = :session_id IF EXISTS",
                InteractionUtil.join(session.toData().keys(), true));
        return new InteractionMappingActionImpl<>(jact, content, session.toMap())
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Void> request, @Nonnull BufferArray array)
            {
                if (InteractionUtil.isDone(array))
                    request.onSuccess(null);
                else
                    request.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_SESSION));
            }
        };
    }

    @Nonnull
    @CheckReturnValue
    public InteractionContextAction<Void> deleteSessionById(@Nonnull UUID userId, @Nonnull UUID sessionId)
    {
        Checks.notNull(userId, "User ID");
        Checks.notNull(sessionId, "Session ID");
        return new InteractionContextActionImpl<>(jact, "DELETE FROM users.sessions WHERE user_id = ? AND session_id = ? IF EXISTS", Arrays.asList(userId, sessionId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Void> request, @Nonnull BufferArray array)
            {
                if (InteractionUtil.isDone(array))
                    request.onSuccess(null);
                else
                    request.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_SESSION));
            }
        };
    }

    @Nonnull
    @CheckReturnValue
    public InteractionContextActionImpl<Void> logout(@Nonnull UUID userId, @Nonnull UUID sessionId)
    {
        Checks.notNull(userId, "User ID");
        Checks.notNull(sessionId, "Session ID");
        return new InteractionContextActionImpl<>(jact, "DELETE FROM users.sessions WHERE user_id = ? AND session_id != ?", Arrays.asList(userId, sessionId));
    }
}
