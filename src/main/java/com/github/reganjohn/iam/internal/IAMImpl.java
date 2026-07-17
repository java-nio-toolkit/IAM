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
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryType;
import com.github.adamorgan.jnt.internal.JNTImpl;
import com.github.adamorgan.jnt.internal.handle.classic.ClassicReceiveHandlerImpl;
import com.github.adamorgan.jnt.internal.managers.*;
import com.github.adamorgan.jnt.internal.requests.restaction.AccessEntryActionImpl;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.adamorgan.jnt.internal.utils.Helpers;
import com.github.reganjohn.iam.api.IAM;
import com.github.reganjohn.iam.api.entities.Application;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.entities.Session;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.api.utils.ClassLoader;
import com.github.reganjohn.iam.api.utils.applications.AccessApplicationCreateData;
import com.github.reganjohn.iam.api.utils.applications.ApplicationCreateData;
import com.github.reganjohn.iam.api.utils.applications.ApplicationEditData;
import com.github.reganjohn.iam.api.utils.sessions.SessionCreateData;
import com.github.reganjohn.iam.api.utils.sessions.SessionEditData;
import com.github.reganjohn.iam.api.utils.users.UserCreateData;
import com.github.reganjohn.iam.api.utils.users.UserEditData;
import com.github.reganjohn.iam.archive.AdaMorganClientV2;
import com.github.reganjohn.iam.internal.managers.ContentSecurityOverrideManagerImpl;
import com.github.reganjohn.iam.internal.managers.ErrorObjectManagerImpl;
import com.github.reganjohn.iam.internal.managers.GlobalAccessManagerImpl;
import com.github.reganjohn.iam.internal.requests.restactions.UserRetrieveActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.application.*;
import com.github.reganjohn.iam.internal.requests.restactions.self.SelfUserCreateActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.self.SelfUserDeleteActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.self.SelfUserEditActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.self.SelfUserRetrieveActionImpl;
import com.github.reganjohn.iam.internal.requests.restactions.session.*;
import com.reganjohn.jact.api.JACT;
import com.reganjohn.jact.api.JACTBuilder;
import com.reganjohn.jact.api.interactions.context.InteractionMapping;
import com.reganjohn.jact.api.requests.Consistency;
import com.reganjohn.jact.api.requests.objaction.InteractionCallbackAction;
import com.reganjohn.jact.api.utils.Compression;
import com.reganjohn.jact.api.utils.data.BufferArray;
import com.reganjohn.jact.internal.JACTImpl;
import com.reganjohn.jact.internal.interactions.InteractionImpl;
import com.reganjohn.jact.internal.interactions.response.InteractionCallbackResponseImpl;
import com.reganjohn.jact.internal.managers.SecretAccessManagerImpl;
import com.reganjohn.jact.internal.requests.objaction.InteractionContextActionImpl;
import com.reganjohn.jact.internal.requests.objaction.InteractionCreateActionImpl;
import com.reganjohn.jact.internal.requests.objaction.InteractionMappingActionImpl;
import com.reganjohn.jact.internal.utils.InteractionUtil;
import io.netty.util.ResourceLeakDetector;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.security.Security;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class IAMImpl implements IAM
{
    public static final Map<String, List<String>> signTypes = new ConcurrentHashMap<>();

    static
    {
        for (SignType signType : SignType.values())
        {
            if (signType.getType() == AccessEntryType.NONE)
                continue;
            List<String> set = signTypes.computeIfAbsent(signType.getType().name(), __ -> new ArrayList<>());
            set.add(signType.getName());
        }
    }

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

    private final EntityBuilder entityBuilder = new EntityBuilder(this);

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
                .addEventListeners(new GlobalAccessManagerImpl(this, SignType.EDDSA, 2, 30, TimeUnit.SECONDS, audiences))
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

                .addEventListenerProvider(() -> new ApplicationCreateActionImpl(this))
                .addEventListenerProvider(() -> new ApplicationPaginationActionImpl(this))
                .addEventListenerProvider(() -> new ApplicationRetrieveActionImpl(this))
                .addEventListenerProvider(() -> new ApplicationEditActionImpl(this))
                .addEventListenerProvider(() -> new ApplicationDeleteActionImpl(this))

                .addEventListenerProvider(() -> new ApplicationAccessActionImpl(this))
                .addEventListenerProvider(() -> new ApplicationSyncActionImpl(this))
                .addEventListenerProvider(() -> new ApplicationRevokeActionImpl(this))

                .addEventListeners(new ErrorObjectManagerImpl(true))
                .build();

        TimeUnit.SECONDS.sleep(5);
        startup();
    }

    public void startup() throws Exception
    {
        try
        {
            String[] statements = {
                    "TRUNCATE global.public_keys",
                    "TRUNCATE users.public_keys",
                    "TRUNCATE integrations.applications",
                    "TRUNCATE integrations.public_keys",
                    "TRUNCATE users.accounts",
                    "TRUNCATE users.permissions",
                    "TRUNCATE users.sessions"
            };

            for (String statement : statements)
            {
                new InteractionCreateActionImpl<Void>(jact, statement).queue();
            }
        }
        finally
        {
            AdaMorganClientV2 clientV2 = new AdaMorganClientV2();
            clientV2.startTest();
        }
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
    public EntityBuilder getEntityBuilder()
    {
        return entityBuilder;
    }

    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<List<AccessEntryData>> retrieveAccessEntries(@Nonnull UUID userId, @Nonnull List<String> thumbprints)
    {
        Checks.notNull(userId, "User ID");
        StringJoiner joiner = new StringJoiner(", ");
        for (int i = 0; i < thumbprints.size(); i++)
            joiner.add("?");
        String content = Helpers.format("SELECT * FROM users.public_keys WHERE user_id = ? AND thumbprint IN (%s)", joiner);
        List<Object> params = new ArrayList<>(Collections.singletonList(userId));
        params.addAll(thumbprints);
        return new InteractionContextActionImpl<>(jact, content, params)
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<List<AccessEntryData>> interaction,
                                      @Nonnull BufferArray array) throws Exception
            {
                if (array.isEmpty())
                    interaction.onSuccess(Collections.emptyList());
                else
                    interaction.onSuccess(entityBuilder.createAccessEntries(array));
            }
        };
    }

    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<User> retrieveUserById(@Nonnull UUID id)
    {
        Checks.notNull(id, "User ID");
        return new InteractionContextActionImpl<>(jact, "SELECT * FROM users.accounts WHERE user_id = ?", Collections.singletonList(id))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<User> request, @Nonnull BufferArray array)
            {
                if (!array.isEmpty())
                    request.onSuccess(entityBuilder.createUser(array.getObject(0)));
                else
                    request.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_USER));
            }
        };
    }

    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<Void> createUser(@Nonnull UserCreateData user)
    {
        Checks.notNull(user, "User");
        return new InteractionMappingActionImpl<>(jact, ClassLoader.getResourceAsString("create_account.cql"), user)
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Void> request, @Nonnull BufferArray array)
            {
                if (array.isEmpty())
                    request.onSuccess(null);
                else
                    request.onFailure(new ErrorResponseException(ErrorResponse.USER_ALREADY_EXISTS));
            }
        };
    }

    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<Void> editUserById(@Nonnull UserEditData user)
    {
        Checks.notNull(user, "User");
        String content = Helpers.format("UPDATE users.accounts SET username = :username, flags = :flags WHERE user_id = :user_id IF EXISTS");
        return new InteractionMappingActionImpl<>(jact, content, user)
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Void> request, @Nonnull BufferArray array)
            {
                if (InteractionUtil.isDone(array))
                    request.onSuccess(null);
                else
                    request.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_USER));
            }
        };
    }

    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<Void> deleteUserById(@Nonnull UUID userId)
    {
        Checks.notNull(userId, "User ID");
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
    public InteractionCallbackAction<List<Session>> retrieveSessions(@Nonnull UUID userId)
    {
        Checks.notNull(userId, "User ID");
        return new InteractionContextActionImpl<>(jact, "SELECT * FROM users.sessions WHERE user_id = ?", Collections.singletonList(userId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<List<Session>> interaction,
                                      @Nonnull BufferArray array)
            {
                interaction.onSuccess(array.isEmpty() ? Collections.emptyList() : entityBuilder.createSessions(array));
            }
        };
    }

    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<Session> retrieveSessionById(@Nonnull UUID userId, @Nonnull UUID sessionId)
    {
        Checks.notNull(userId, "User ID");
        Checks.notNull(sessionId, "Session ID");
        return new InteractionContextActionImpl<>(jact, "SELECT * FROM users.sessions WHERE user_id = ? AND session_id = ?", Arrays.asList(userId, sessionId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Session> interaction,
                                      @Nonnull BufferArray array)
            {
                if (array.isEmpty())
                    interaction.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_SESSION));
                else
                    interaction.onSuccess(entityBuilder.createSession(array.getObject(0)));
            }
        };
    }

    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<AccessEntryData> retrieveAccessEntryById(@Nonnull UUID userId, @Nonnull String thumbprint)
    {
        Checks.notNull(userId, "User ID");
        Checks.notEmpty(thumbprint, "Thumbprint");
        return new InteractionContextActionImpl<>(jact, "SELECT * FROM users.public_keys WHERE user_id = ? AND thumbprint = ?", Arrays.asList(userId, thumbprint))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<AccessEntryData> interaction,
                                      @Nonnull BufferArray array) throws Exception
            {
                if (array.isEmpty())
                    interaction.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_ACCESS));
                else
                    interaction.onSuccess(entityBuilder.createAccessEntry(array.getObject(0)));
            }
        };
    }

    @Nonnull
    public InteractionCallbackAction<Void> createSession(@Nonnull SessionCreateData session)
    {
        Checks.notNull(session, "Session");
        return new InteractionMappingActionImpl<>(jact, ClassLoader.getResourceAsString("create_session.cql"), session.toMap())
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
    public InteractionCallbackAction<Integer> retrieveSessionCount(@Nonnull UUID userId)
    {
        Checks.notNull(userId, "User ID");
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
    public InteractionCallbackAction<Void> editSession(@Nonnull SessionEditData session)
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
    public InteractionCallbackAction<Void> deleteSessionById(@Nonnull Session session)
    {
        Checks.notNull(session, "Session");
        InteractionMapping map = new InteractionMapping.Builder()
                .put("user_id", session.getUserId())
                .put("session_id", session.getUniqueId())
                .put("thumbprint", session.getThumbprint())
                .build();
        return new InteractionMappingActionImpl<>(jact, ClassLoader.getResourceAsString("delete_session.cql"), map)
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Void> request, @Nonnull BufferArray array)
            {
                if (!array.isEmpty())
                    request.onSuccess(null);
                else
                    request.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_SESSION));
            }
        };
    }


    //todo: add logics!
    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<Void> logout(@Nonnull UUID userId, @Nonnull UUID sessionId)
    {
        Checks.notNull(userId, "User ID");
        Checks.notNull(sessionId, "Session ID");
        return retrieveSessionById(userId, sessionId).flatMap(session ->
        {
            InteractionMapping map = new InteractionMapping.Builder()
                    .put("user_id", session.getUserId())
                    .put("session_id", session.getUniqueId())
                    .put("thumbprint", session.getThumbprint())
                    .build();
            return new InteractionMappingActionImpl<>(jact, ClassLoader.getResourceAsString("logout.cql"), map);
        });
    }

    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<Integer> retrieveApplicationCount(@Nonnull UUID userId)
    {
        return new InteractionContextActionImpl<>(jact, "SELECT * FROM integrations.applications WHERE user_id = :user_id", Collections.singletonList(userId))
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
    public InteractionCallbackAction<Void> createApplication(@Nonnull ApplicationCreateData application)
    {
        Checks.notNull(application, "Application");
        return new InteractionMappingActionImpl<>(jact, ClassLoader.getResourceAsString("create_application.cql"), application.toMap())
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Void> request, @Nonnull BufferArray array)
            {
                if (array.isEmpty())
                    request.onSuccess(null);
                else
                    request.onFailure(new ErrorResponseException(ErrorResponse.APPLICATION_ALREADY_EXISTS));
            }
        };
    }

    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<List<Application>> retrieveApplications(@Nonnull UUID userId)
    {
        Checks.notNull(userId, "User ID");
        return new InteractionContextActionImpl<>(jact, "SELECT * FROM integrations.applications WHERE user_id = ?", Collections.singletonList(userId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<List<Application>> interaction,
                                      @Nonnull BufferArray array) throws Exception
            {
                interaction.onSuccess(array.isEmpty() ? Collections.emptyList() : entityBuilder.createApplications(array));
            }
        };
    }


    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<Application> retrieveApplicationById(@Nonnull UUID userId,
                                                                          @Nonnull UUID applicationId)
    {
        Checks.notNull(userId, "User ID");
        Checks.notNull(applicationId, "Application ID");
        return new InteractionContextActionImpl<>(jact, "SELECT * FROM integrations.applications WHERE user_id = ? AND application_id = ?", Arrays.asList(userId, applicationId))
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Application> interaction,
                                      @Nonnull BufferArray array)
            {
                if (array.isEmpty())
                    interaction.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_APPLICATION));
                else
                    interaction.onSuccess(entityBuilder.createApplication(array.getObject(0)));
            }
        };
    }

    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<Integer> retrieveApplicationAccessCount(@Nonnull Application application)
    {
        Checks.notNull(application, "Application");
        return new InteractionContextActionImpl<>(jact, "SELECT COUNT(*) FROM integrations.public_keys WHERE user_id = ? AND application_id = ?", Arrays.asList(application.getOwnerId(), application.getUniqueId()))
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
    public InteractionCallbackAction<Void> createApplicationAccessEntry(@Nonnull AccessApplicationCreateData access)
    {
        Checks.notNull(access, "Access Application");
        return new InteractionMappingActionImpl<>(jact, ClassLoader.getResourceAsString("create_access_application.cql"), access.toMap())
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Void> interaction,
                                      @Nonnull BufferArray array)
            {
                if (array.isEmpty())
                    interaction.onSuccess(null);
                else
                    interaction.onFailure(new ErrorResponseException(ErrorResponse.ACCESS_ALREADY_EXISTS));
            }
        };
    }

    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<Void> deleteApplicationAccessEntry(@Nonnull UUID userId,
                                                                        @Nonnull UUID applicationId,
                                                                        @Nonnull String thumbprint)
    {
        Checks.notNull(userId, "User ID");
        Checks.notNull(applicationId, "Application ID");
        Checks.notEmpty(thumbprint, "Thumbprint");
        InteractionMapping map = new InteractionMapping.Builder()
                .put("user_id", userId)
                .put("application_id", applicationId)
                .put("thumbprint", thumbprint)
                .build();
        return new InteractionMappingActionImpl<>(jact, ClassLoader.getResourceAsString("delete_access_application.cql"), map)
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Void> interaction,
                                      @Nonnull BufferArray array)
            {
                interaction.onSuccess(null);
            }
        };
    }

    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<Void> editApplication(@Nonnull ApplicationEditData application)
    {
        Checks.notNull(application, "Application");
        String content = Helpers.format("UPDATE integrations.applications SET %s WHERE user_id = :user_id AND application_id = :application_id IF EXISTS",
                InteractionUtil.join(application.toData().keys(), true));
        return new InteractionMappingActionImpl<>(jact, content, application.toMap())
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Void> request, @Nonnull BufferArray array)
            {
                if (InteractionUtil.isDone(array))
                    request.onSuccess(null);
                else
                    request.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_APPLICATION));
            }
        };
    }


    @Nonnull
    @CheckReturnValue
    public InteractionCallbackAction<Void> deleteApplicationById(@Nonnull Application application)
    {
        Checks.notNull(application, "Application");
        InteractionMapping map = new InteractionMapping.Builder()
                .put("user_id", application.getOwnerId())
                .put("application_id", application.getUniqueId())
                .build();
        return new InteractionMappingActionImpl<>(jact, ClassLoader.getResourceAsString("delete_application.cql"), map)
        {
            @Override
            public void handleSuccess(@Nonnull InteractionCallbackResponseImpl response,
                                      @Nonnull InteractionImpl<Void> request, @Nonnull BufferArray array)
            {
                if (!array.isEmpty())
                    request.onSuccess(null);
                else
                    request.onFailure(new ErrorResponseException(ErrorResponse.UNKNOWN_SESSION));
            }
        };
    }
}
